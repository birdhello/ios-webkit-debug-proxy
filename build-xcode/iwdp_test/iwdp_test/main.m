#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>

#include "usbmuxd_util.h"
#include "message_util.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        int fd = usbmuxd_connect_file(-1);
        if (fd < 0) {
            return fd;
        }
        int result = usbmuxd_device_listener(fd);
        if (result < 0) {
            close(fd);
            return result;
        }

        while (1) {
            result = usbmuxd_on_loop();
            if (result < 0) {
                return result;
            }
        } // while(1)

    } // @autoreleasepool
    return 0;
}
