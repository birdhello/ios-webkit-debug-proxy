#pragma once

#include <stdbool.h>

#include <plist/plist.h>

typedef struct ssl_st SSL;

int plist_util_get_string(plist_t plist, const char *key, char **dest);

int plist_util_get_bool(plist_t plist, const char *key, bool *dest);

int plist_util_send_by_fd(int fd, plist_t plist);

int plist_util_send_by_ssl(SSL *ssl, plist_t plist);
