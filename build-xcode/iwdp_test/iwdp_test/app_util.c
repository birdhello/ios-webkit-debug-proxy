#include "app_util.h"

#include <stdlib.h>
#include <string.h>

#include "logger.h"
#include "plist_util.h"
#include "map_util.h"
#include "page_util.h"

static Map *app_map_ = NULL;

__attribute__((constructor)) static void app_map_constructor(void) {
    app_map_ = map_create();
}

__attribute__((destructor)) static void app_map_destructor(void) {
    map_delete(app_map_);
}

struct App_ {
    char *id;
    char *name;
    bool isProxy;

    int fd;
    SSL *ssl;
    const char *connectionID;
};

static int app_to_string_(App *app, char **out) {
    return asprintf(out,
                    "id: %s"
                    "\n\t name: %s"
                    "\n\t connectionID: %s"
                    "\n\t isProxy: %d"
                    "\n\t fd: %d"
                    "\n\t ssl: %p"
                    "\n"
                    , app->id, app->name, app->connectionID
                    , app->isProxy, app->fd, app->ssl);
}


static void app_clear_(App *app) {
    plist_mem_free(app->id);
    plist_mem_free(app->name);
    memset(app, 0, sizeof(App));
}

static App *app_new_(void) {
    return calloc(1, sizeof(App));
}

static void app_delete_(App *app) {
    app_clear_(app);
    free(app);
}

static App *app_news_(size_t len) {
    return (App *) calloc(len + 1, sizeof(App));
}

static void app_deletes_(App *apps) {
    App *app = apps;
    while (app->id) {
        app_clear_(app);
        ++app;
    }
    free(apps);
}

App *app_get(const char *appID) {
    return map_get(app_map_, map_create_key_by_str(appID));
}

static int app_forward_get_listing_(App *app) {
    plist_t args = plist_new_dict();
    plist_dict_set_item(args, "WIRConnectionIdentifierKey", plist_new_string(app->connectionID));
    plist_dict_set_item(args, "WIRApplicationIdentifierKey", plist_new_string(app->id));


    plist_t rpc_dict = plist_new_dict();
    plist_dict_set_item(rpc_dict, "__selector", plist_new_string("_rpc_forwardGetListing:"));

    plist_dict_set_item(rpc_dict, "__argument", args);

    int ret;
    SSL *ssl = app->ssl;
    if (ssl) {
        ret = plist_util_send_by_ssl(ssl, rpc_dict);
    } else {
        ret = plist_util_send_by_fd(app->fd, rpc_dict);
    }
    plist_free(rpc_dict);
    return ret;
}

int app_list_update(int fd, SSL *ssl, const char *connectionID, plist_t list) {
    if (!list) {
      return -1;
    }

    if (plist_get_node_type(list) != PLIST_DICT) {
      return -1;
    }
    plist_dict_iter iter = NULL;
    plist_dict_new_iter(list, &iter);
    if (!iter) {
        return -1;
    }
    size_t length = plist_dict_get_size(list);
    App *apps = app_news_(length);
    if (!apps) {
        return -1;
    }

    char *key = NULL;
    plist_t value = NULL;
    for (int index = 0; index < length; ) {
        plist_dict_next_item(list, iter, &key, &value);
        if (value) {
            App *app = &apps[index];
            if (plist_util_get_string(value, "WIRApplicationIdentifierKey", &app->id) < 0 ||
                plist_util_get_string(value, "WIRApplicationNameKey", &app->name) < 0 ||
                plist_util_get_bool(value, "WIRIsApplicationProxyKey", &app->isProxy) < 0) {
                app_clear_(app);
                continue;
            }
            app->fd = fd;
            app->ssl = ssl;
            app->connectionID = connectionID;

            char *appStr;
            if (app_to_string_(app, &appStr) > 0) {
                LogD("app: \n\t %s", appStr)
                free(appStr);
            }

            app_forward_get_listing_(app);
            ++index;
        } else {
            break;
        }
    }
    return 0;
}

int app_connected(int fd, SSL *ssl, const char *connectionID, plist_t app) {
    App *appInfo = app_new_();
    if (plist_util_get_string(app, "WIRApplicationIdentifierKey", &appInfo->id) < 0 ||
        plist_util_get_string(app, "WIRApplicationNameKey", &appInfo->name) < 0 ||
        plist_util_get_bool(app, "WIRIsApplicationProxyKey", &appInfo->isProxy) < 0) {
        app_delete_(appInfo);
        return -1;
    }
    appInfo->fd = fd;
    appInfo->ssl = ssl;
    appInfo->connectionID = connectionID;
    
    char *appStr;
    if (app_to_string_(appInfo, &appStr) > 0) {
        LogD("app: \n\t %s", appStr)
        free(appStr);
    }

    app_forward_get_listing_(appInfo);
    app_delete_(appInfo);
    return 0;
}

int app_on_sent_listing(App *app, plist_t list) {
    size_t listSize = plist_dict_get_size(list);
    plist_dict_iter iter = NULL;
    plist_dict_new_iter(list, &iter);
    for (size_t i = 0; i < listSize; i++) {
        char *key = NULL;
        plist_t page = NULL;
        plist_dict_next_item(list, iter, &key, &page);
        page_update(app->fd, app->ssl, app->connectionID, page);
        free(key);
    }
    return 0;
}
