#include "fd_util.h"

#include <stdio.h>

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>

int fd_set_timeout(int fd, int timeout) {
    if (timeout < 0) {
        int opts = fcntl(fd, F_GETFL);
        // O_NONBLOCK: 非阻塞模式。默认是阻塞模式
        if (!opts || fcntl(fd, F_SETFL, (opts | O_NONBLOCK)) < 0) {
            printf("%s:%d %s| Could not set socket to non-blocking\n",
                   __FILE__, __LINE__, __FUNCTION__);
            return -1;
        }
    } else {
        long millis = (timeout > 0 ? timeout : 5000);
        struct timeval tv;
        tv.tv_sec = (time_t) (millis / 1000);
        tv.tv_usec = (__darwin_suseconds_t) ((millis - (tv.tv_sec * 1000)) * 1000);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
                       sizeof(tv))) {
            printf("%s:%d %s| Could not set socket receive timeout\n",
                   __FILE__, __LINE__, __FUNCTION__);
            return -1;
        }
    }
    return 0;
}
