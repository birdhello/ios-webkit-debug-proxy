#pragma once

#include <stddef.h>

int usbmuxd_connect_file(int recv_timeout);

int usbmuxd_device_listener(int fd);

int usbmuxd_on_recv(const char *data, size_t length);

int usbmuxd_on_loop(void);
