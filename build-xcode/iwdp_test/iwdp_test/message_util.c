#include "message_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/socket.h>

#include <openssl/ssl.h>

#define FD_SET_SIZE sizeof(struct fd_set)

int fd_send(int fd, const char *data, size_t length) {
    while (length != 0) {
        ssize_t sent_bytes = send(fd, (const void *) data, length, 0);
        if (sent_bytes <= 0) {
            printf("fd: %d send failed, sent_bytes: %zi\n", fd, sent_bytes);
            return -1;
        }
        data += sent_bytes;
        length -= sent_bytes;
    }
    return 0;
}

int ssl_send(SSL *ssl, const char *data, size_t length) {
    int write_length;
    while (length != 0) {
        if (length > INT_MAX) {
            write_length = INT_MAX;
        } else {
            write_length = (int) length;
        }

        int sent_bytes = SSL_write(ssl, (const void *) data, write_length);
        if (sent_bytes <= 0) {
            int error = SSL_get_error(ssl, sent_bytes);
            printf("%s:%d %s| ssl: %p SSL_write error code: %d, sent_bytes: %d\n",
                   __FILE__, __LINE__, __FUNCTION__,
                   ssl, error, sent_bytes);
            return -1;
        }
        data += sent_bytes;
        length -= sent_bytes;
    }
    return 0;
}

int fd_recv(int fd, message_on_recv on_recv) {
    const int tmp_buf_length = 4096;
    char *tmp_buf[tmp_buf_length];

    ssize_t read_bytes;
    while (1) {
        read_bytes = recv(fd, tmp_buf, tmp_buf_length, 0);
        if (read_bytes < 0) {
            if (errno != EWOULDBLOCK) {
                printf("fd: %d recv failed, sent_bytes: %zi\n", fd, read_bytes);
                return -1;
            } else {
                return 0;
            }
        } else if (read_bytes == 0) {
            return 0;
        }
        printf("%s:%d %s| fd: %d, bytes: %zi\n",
               __FILE__, __LINE__, __FUNCTION__,
               fd, read_bytes);
        int result = on_recv((const char *) tmp_buf, read_bytes);
        if (result < 0) {
            return result;
        }
    }
}

int ssl_recv(SSL *ssl, message_on_recv on_recv) {
    const int tmp_buf_length = 4096;
    char *tmp_buf[tmp_buf_length];

    ssize_t read_bytes;
    while (1) {
        read_bytes = SSL_read(ssl, tmp_buf, tmp_buf_length);
        if (read_bytes < 0) {
            int error = SSL_get_error(ssl, (int) read_bytes);
            printf("%s:%d %s| ssl: %p SSL_read error code: %d, read_bytes: %zi\n",
                   __FILE__, __LINE__, __FUNCTION__,
                   ssl, error, read_bytes);
            return -1;
        } else if (read_bytes == 0) {
            return 0;
        }

        int result = on_recv((const char *) tmp_buf, read_bytes);
        if (result < 0) {
            return result;
        }
    }
}

int message_select(fd_set fdSet, int max_fd, message_on_recv on_recv) {
    struct timeval timeout;
    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = 2;

    fd_set temp_read_fds, temp_write_fds, temp_error_fds;
    FD_ZERO(&temp_read_fds);
    FD_ZERO(&temp_write_fds);
    FD_ZERO(&temp_error_fds);

    memcpy(&temp_read_fds, &fdSet, FD_SET_SIZE);
    memcpy(&temp_write_fds, &fdSet, FD_SET_SIZE);
    memcpy(&temp_error_fds, &fdSet, FD_SET_SIZE);

    int num_ready = select(max_fd + 1, &temp_read_fds, &temp_write_fds, &temp_error_fds, &timeout);
    if (num_ready == 0) {
        return 0;
    } else if (num_ready < 0) {
        if (errno != EINTR && errno != EAGAIN) {
          // might want to sleep here?
          printf("select failed\n");
          return -errno;
        }
        return 0;
    } else {
        int current_fd = 0;
        for (; current_fd <= max_fd; ++current_fd) {
            bool can_recv = FD_ISSET(current_fd, &temp_read_fds);
            bool can_send = FD_ISSET(current_fd, &temp_write_fds);
            bool is_fail = FD_ISSET(current_fd, &temp_error_fds);
            if (!can_send && !can_recv && !is_fail) {
                continue;
            }
            if (is_fail) {
                // dispatch on_error with current_fd
                return -1;
            }
            if (can_send) {
                // TODO
            }
            if (can_recv) {
                fd_recv(current_fd, on_recv);
            }
        } // for
    }
    return 0;
}
