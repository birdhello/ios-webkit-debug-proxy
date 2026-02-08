#pragma once

#include <plist/plist.h>

typedef struct ssl_st SSL;

typedef struct App_ App;

App *app_get(const char *appID);

int app_list_update(int fd, SSL *ssl, const char *connectionID, plist_t list);

int app_connected(int fd, SSL *ssl, const char *connectionID, plist_t app);

int app_on_sent_listing(App *app, plist_t list);
