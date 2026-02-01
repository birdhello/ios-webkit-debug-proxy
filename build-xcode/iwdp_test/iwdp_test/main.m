#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#import <Foundation/Foundation.h>

#include <plist/plist.h>

#define USBMUXD_SOCKET_PORT 27015
#define USBMUXD_FILE_PATH "/var/run/usbmuxd"
#define TYPE_PLIST 8
#define LIBUSBMUX_VERSION 3

char *dl_sprintf_uint32(char *buf, uint32_t value) {
    char *tail = buf;
    int8_t i;
    for (i = 0; i < 4; i++) {
        *tail++ = (unsigned char)((value >> (i<<3)) & 0xFF);
    }
    return tail;
}

int sm_send(int fd, const char *data, size_t length, void* value) {
    sm_private_t my = self->private_state;
    sm_sendq_t sendq = (sm_sendq_t)ht_get_value(my->fd_to_sendq, HT_KEY(fd));
    const char *head = data;
    const char *tail = data + length;
    if (!sendq) {
        void *ssl_session = ht_get_value(my->fd_to_ssl, HT_KEY(fd));
        // send as much as we can without blocking
        while (1) {
            ssize_t sent_bytes;
            if (ssl_session == NULL) {
                sent_bytes = send(fd, (void*)head, (tail - head), 0);
                if (sent_bytes <= 0) {
                        if (sent_bytes && errno != EWOULDBLOCK) {
                            sm_on_debug(self, "ss.failed fd=%d", fd);
                            perror("send failed");
                            return SM_ERROR;
                        }
                        break;
                    }
                } else {
                    sent_bytes = SSL_write((SSL *)ssl_session, (void*)head, tail - head);
                    if (sent_bytes <= 0) {
                        if (SSL_get_error(ssl_session, sent_bytes) != SSL_ERROR_WANT_READ &&
                            SSL_get_error(ssl_session, sent_bytes) != SSL_ERROR_WANT_WRITE) {
                            sm_on_debug(self, "ss.failed fd=%d", fd);
                            perror("ssl send failed");
                            return SM_ERROR;
                        }
                        break;
                    }
                }
                head += sent_bytes;
                if (head >= tail) {
                    self->on_sent(self, fd, value, data, length);
                    return SM_SUCCESS; // this is the typical case
                }
            }
        }
        // we can't send this now, so queue it
        int curr_recv_fd = my->curr_recv_fd;
        sm_sendq_t newq = sm_sendq_new(curr_recv_fd, value, head, tail - head);
        if (sendq) {
            while (sendq->next) {
                sendq = sendq->next;
            }
            sendq->next = newq;
        } else {
            ht_put(my->fd_to_sendq, HT_KEY(fd), newq);
            FD_SET(fd, my->send_fds);
        }
        sm_on_debug(self, "ss.sendq<%p> new fd=%d recv_fd=%d length=%zd"
                    ", prev=<%p>", newq, fd, curr_recv_fd, tail - head, sendq);
        if (curr_recv_fd && FD_ISSET(curr_recv_fd, my->recv_fds)) {
            // block the current recv_fd, to prevent our sendq from growing too large.
            // At worst our recv_fds are all trying to send to the same fd, in which
            // case we'll eventually block all of them until the first blocked send
            // succeeds.
            sm_on_debug(self, "ss.sendq<%p> disable recv_fd=%d", newq, curr_recv_fd);
            FD_CLR(curr_recv_fd, my->recv_fds);
            FD_CLR(curr_recv_fd, my->tmp_recv_fds);
        }
        return SM_SUCCESS;
    }

int connect_(int recv_timeout) {
    int fd = -1;

    const char *filename = USBMUXD_FILE_PATH;
    struct stat fst;
    if (stat(filename, &fst) ||
        !S_ISSOCK(fst.st_mode) ||
        (fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    struct sockaddr_un name;
    name.sun_family = AF_LOCAL;
    strncpy(name.sun_path, filename, sizeof(name.sun_path));
    name.sun_path[sizeof(name.sun_path) - 1] = 0;
    size_t size = SUN_LEN(&name);
    if (connect(fd, (struct sockaddr *)&name, (socklen_t) size) < 0) {
        close(fd);
        return -1;
    }

    if (recv_timeout < 0) {
        int opts = fcntl(fd, F_GETFL);
        if (!opts || fcntl(fd, F_SETFL, (opts | O_NONBLOCK)) < 0) {
            perror("Could not set socket to non-blocking");
        }
    } else {
        long millis = (recv_timeout > 0 ? recv_timeout : 5000);
        struct timeval tv;
        tv.tv_sec = (time_t) (millis / 1000);
        tv.tv_usec = (time_t) ((millis - (tv.tv_sec * 1000)) * 1000);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
                       sizeof(tv))) {
            perror("Could not set socket receive timeout");
        }
    }
    return fd;
}

int start_(int fd) {
    // Assume usbmuxd supports proto_version 1.  If not then we'd need to
    // send a binary listen request, check for failure, then retry this:
    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "ClientVersionString", plist_new_string("device_listener"));
    if (plist_dict_get_size(dict) != 1) {
        perror("Detected an old copy of libplist?!  For a fix, see:\n"
               "https://github.com/libimobiledevice/libimobiledevice/issues/"
               "68#issuecomment-38994545");
        return -1;
    }
    plist_dict_set_item(dict, "MessageType", plist_new_string("Listen"));
    plist_dict_set_item(dict, "ProgName", plist_new_string("libusbmuxd"));
    plist_dict_set_item(dict, "kLibUSBMuxVersion", plist_new_uint(LIBUSBMUX_VERSION));
    char *xml = NULL;
    uint32_t xml_length = 0;
    plist_to_xml(dict, &xml, &xml_length);
    plist_free(dict);

    size_t length = 16 + xml_length;
    char *packet = (char *)calloc(length, sizeof(char));
    if (!packet) {
        return -1;
    }
    char *tail = packet;
    tail = dl_sprintf_uint32(tail, length);
    tail = dl_sprintf_uint32(tail, 1); // version: 1
    tail = dl_sprintf_uint32(tail, TYPE_PLIST); // type: plist
    tail = dl_sprintf_uint32(tail, 1); // tag: 1
    strncpy(tail, xml, xml_length);
    free(xml);

    int ret = send_packet_(packet, length);
    free(packet);
    return ret;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        int fd = connect_(-1);
    }
    return 0;
}
