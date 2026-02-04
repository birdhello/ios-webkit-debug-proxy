#include "usbmuxd_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <plist/plist.h>

#include "message_util.h"
#include "fd_util.h"
#include "device.h"

#define USBMUXD_FILE_PATH "/var/run/usbmuxd"
#define LIBUSBMUX_VERSION 3
#define TYPE_PLIST 8

static fd_set fd_set_;
static int max_fd_ = -1;

__attribute__((constructor)) static void usbmuxd_init(void) {
    FD_ZERO(&fd_set_);
}

int usbmuxd_connect_file(int recv_timeout) {
    const char *filename = USBMUXD_FILE_PATH;
    struct stat fst;
    if (stat(filename, &fst)) {
        return -1;
    }
    if (!S_ISSOCK(fst.st_mode)) {
        return -1;
    }
    int fd = -1;
    if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
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

    fd_set_timeout(fd, recv_timeout);

    FD_SET(fd, &fd_set_);
    if (max_fd_ < fd) {
        max_fd_ = fd;
    }

    return fd;
}

static char *sprintf_uint32_(char *buf, uint32_t value) {
    char *tail = buf;
    int8_t i;
    for (i = 0; i < 4; i++) {
        *tail++ = (unsigned char)((value >> (i<<3)) & 0xFF);
    }
    return tail;
}

int usbmuxd_device_listener(int fd) {
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
    tail = sprintf_uint32_(tail, (uint32_t) length);
    tail = sprintf_uint32_(tail, 1); // version: 1
    tail = sprintf_uint32_(tail, TYPE_PLIST); // type: plist
    tail = sprintf_uint32_(tail, 1); // tag: 1
    strncpy(tail, xml, xml_length);
    free(xml);

    int ret = fd_send(fd, packet, length);
    free(packet);
    return ret;
}

static uint32_t dl_sscanf_uint32(const char *buf) {
    uint32_t ret = 0;
    const char *tail = buf;
    int8_t i;
    for (i = 0; i < 4; i++) {
        ret |= ((((unsigned char) *tail++) & 0xFF) << (i<<3));
    }
    return ret;
}

static int usb_muxd_on_recv_(const char *packet, size_t length) {
    const char *tail = packet;
    uint32_t len = dl_sscanf_uint32(tail);
    tail += 4;
    if (len != length || len < 16) {
        return -1;
    }
    uint32_t version = dl_sscanf_uint32(tail);
    tail += 4;
    uint32_t type = dl_sscanf_uint32(tail);
    tail += 4;
    (void)dl_sscanf_uint32(tail);
    tail += 4;
    const char *xml = tail;
    size_t xml_length = length - 16;

    if (version != 1 || type != TYPE_PLIST) {
        return 0; // ignore?
    }

    plist_t dict = NULL;
    plist_from_xml(xml, (uint32_t) xml_length, &dict);
    char *messageType = NULL;
    if (dict) {
        char *json_data = NULL;
        uint32_t json_length = 0;
        plist_err_t plistErrorCode = plist_to_openstep(dict, &json_data, &json_length, true);
        if (plistErrorCode == PLIST_ERR_SUCCESS) {
            printf("%s:%d %s| \n%s\n", __FILE__, __LINE__, __FUNCTION__, json_data);
            free(json_data);
        } else {
            printf("%s:%d %s| plist_to_json error code: %d, type: %d, xml: \n%s\n",
                   __FILE__, __LINE__, __FUNCTION__,
                   plistErrorCode, plist_get_node_type(dict), xml);
        }

        plist_t node = plist_dict_get_item(dict, "MessageType");
        if (plist_get_node_type(node) == PLIST_STRING) {
            plist_get_string_val(node, &messageType);
        }
    }

    int ret = -1;
    if (!messageType) {
        ret = -1;
        printf("%s:%d %s| invalid message type\n", __FILE__, __LINE__, __FUNCTION__);
    } else if (!strcmp(messageType, "Result")) {
        plist_t node = plist_dict_get_item(dict, "Number");
        if (node) {
            uint64_t value = 0;
            plist_get_uint_val(node, &value);
            // just an ack of our Listen?
            ret = (value ? -1 : 0);
        }
    } else if (!strcmp(messageType, "Attached")) {
        plist_t props = plist_dict_get_item(dict, "Properties");
        if (props) {
            uint64_t device_num = 0;
            plist_t node = plist_dict_get_item(props, "DeviceID");
            plist_get_uint_val(node, &device_num);

            uint64_t product_id = 0;
            node = plist_dict_get_item(props, "ProductID");
            plist_get_uint_val(node, &product_id);

            char *device_id = NULL;
            node = plist_dict_get_item(props, "SerialNumber");
            if (node) {
                plist_get_string_val(node, &device_id);

                if (device_id && strlen(device_id) == 24) {
                    char *new_device_id = malloc(sizeof(char) * 26);

                    memcpy(new_device_id, device_id, 8);
                    memcpy(new_device_id + 9, device_id + 8, 17);
                    new_device_id[8] = '-';

                    free(device_id);
                    device_id = new_device_id;
                }
            }

            uint64_t location = 0;
            node = plist_dict_get_item(props, "LocationID");
            plist_get_uint_val(node, &location);

            printf("%s:%d %s| device_id: %s\n", __FILE__, __LINE__, __FUNCTION__, device_id);
            ret = device_attach(device_id, (int) device_num);
        }
    } else if (strcmp(messageType, "Detached") == 0) {
        plist_t node = plist_dict_get_item(dict, "DeviceID");
        if (node) {
            uint64_t device_num = 0;
            plist_get_uint_val(node, &device_num);
            printf("device_num: %" PRIu64"\n", device_num);

            char *device_id = NULL;
//            if (device_id) {
//                on_detach_(device_id, (int)device_num);
//                free(device_id);
//            }
        }
    }
    free(messageType);
    plist_free(dict);
    return ret;
}

static int usbmuxd_on_recv_(const char *data, size_t length) {
    bool has_body_length = false;
    size_t body_length = 0;
    size_t data_length = length;
    while (1) {
        if (!has_body_length && data_length >= 4) {
            // can read body_length now
            size_t len = dl_sscanf_uint32(data);
            body_length = len;
            has_body_length = true;
            // don't advance in_head yet
        } else if (has_body_length && data_length >= body_length) {
            // can read body now
            int ret = usb_muxd_on_recv_(data, body_length);
            data += body_length;
            data_length -= body_length;
            has_body_length = false;
            body_length = 0;
            if (ret < 0) {
                return ret;
            }
        } else {
            // need more input
            printf("%s:%d %s| need more input, data length origin: %zu, current: %zu\n",
                   __FILE__, __LINE__, __FUNCTION__, length, data_length);
            return 0;
        }
    }
}

static int usbmuxd_on_recv_ready_(int fd) {
    return fd_recv(fd, usbmuxd_on_recv_);
}

int usbmuxd_on_loop(void) {
    int result = message_select(fd_set_, max_fd_, usbmuxd_on_recv_ready_);
    if (result < 0) {
        return result;
    }
    result = device_on_loop();
    if (result < 0) {
        return result;
    }
    return result;
}
