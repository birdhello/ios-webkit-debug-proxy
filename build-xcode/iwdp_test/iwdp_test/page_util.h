#pragma once

typedef void *plist_t;

typedef struct ssl_st SSL;

typedef struct Page_ Page;

int page_update(int fd, SSL *ssl, char *deviceConnectionID, plist_t pagePlist);

