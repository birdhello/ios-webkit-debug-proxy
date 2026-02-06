#pragma once

#include <plist/plist.h>

typedef struct ssl_st SSL;

int app_list_update(int fd, SSL *ssl, const char *connectionID, plist_t list);

int app_connected(int fd, SSL *ssl, const char *connectionID, plist_t app);
