#include "page_util.h"

#include <stdlib.h>

#include <plist/plist.h>

#include "logger.h"
#include "plist_util.h"
#include "map_util.h"

static Map *page_map_ = NULL;

__attribute__((constructor)) static void page_map_constructor(void) {
    page_map_ = map_create();
}

__attribute__((destructor)) static void page_map_destructor(void) {
    map_delete(page_map_);
}

struct Page_ {
    uint64_t id;
    char *title;
    char *type;
    char *connectionID;

    int fd;
    SSL *ssl;
    const char *deviceConnectionID;
};

static int page_to_string_(Page *page, char **outString) {
    if (!page || !outString) {
        return -1;
    }
    int needed = snprintf(NULL, 0,
                          "id: %llu, title: %s, type: %s, connectionID: %s, "
                          "deviceConnectionID: %s, fd: %d, ssl: %p",
                          page->id,
                          page->title ? page->title : "NULL",
                          page->type ? page->type : "NULL",
                          page->connectionID ? page->connectionID : "NULL",
                          page->deviceConnectionID ? page->deviceConnectionID : "NULL",
                          page->fd,
                          page->ssl);
    *outString = (char *) malloc(needed + 1);
    if (!*outString) {
        return -1;
    }
    snprintf(*outString, needed + 1,
             "id: %llu, title: %s, type: %s, connectionID: %s, "
             "deviceConnectionID: %s, fd: %d, ssl: %p",
             page->id,
             page->title ? page->title : "NULL",
             page->type ? page->type : "NULL",
             page->connectionID ? page->connectionID : "NULL",
             page->deviceConnectionID ? page->deviceConnectionID : "NULL",
             page->fd,
             page->ssl);
    return needed;
}

static Page *page_new_(void) {
    return calloc(1, sizeof(Page));
}

static void page_delete_(Page *pate) {
    
}

int page_update(int fd, SSL *ssl, char *deviceConnectionID, plist_t pagePlist) {
    uint64_t pageID;
    if (plist_util_get_uint64(pagePlist, "WIRPageIdentifierKey", &pageID) < 0) {
        return -1;
    }
    Page *page = map_get(page_map_, map_create_key_by_int(pageID));
    if (!page) {
        page = page_new_();
    }
    page->id = pageID;
    page->fd = fd;
    page->ssl = ssl;
    page->deviceConnectionID = deviceConnectionID;
    plist_util_get_string(pagePlist, "WIRTitleKey", &page->title);
    plist_util_get_string(pagePlist, "WIRTypeKey", &page->type);

    char *pageString;
    if (page_to_string_(page, &pageString) > 0) {
        LogD("page: \n\t%s", pageString)
        free(pageString);
    }

    return 0;
}
