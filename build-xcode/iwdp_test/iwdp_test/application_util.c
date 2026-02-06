#include "application_util.h"

#include <stdlib.h>
#include <string.h>

#include "plist_util.h"

typedef struct {
    char *id;
    char *name;
    bool isProxy;

    int fd;
    SSL *ssl;
    const char *connectionID;
} AppInfo_;

static void app_clear_(AppInfo_ *app) {
    plist_mem_free(app->id);
    plist_mem_free(app->name);
    memset(app, 0, sizeof(AppInfo_));
}

static AppInfo_ *app_new_(void) {
    return malloc(sizeof(AppInfo_));
}

static void app_delete_(AppInfo_ *app) {
    app_clear_(app);
    free(app);
}

static AppInfo_ *app_news_(size_t len) {
    return (AppInfo_ *) calloc(len + 1, sizeof(AppInfo_));
}

static void app_deletes_(AppInfo_ *apps) {
    AppInfo_ *app = apps;
    while (app->id) {
        app_clear_(app);
        ++app;
    }
    free(apps);
}

static int app_forward_get_listing_(AppInfo_ *app) {
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
    AppInfo_ *apps = app_news_(length);
    if (!apps) {
        return -1;
    }

    char *key = NULL;
    plist_t value = NULL;
    for (int index = 0; index < length; ) {
        plist_dict_next_item(list, iter, &key, &value);
        if (value) {
            AppInfo_ *app = &apps[index];
            if (plist_util_get_string(value, "WIRApplicationIdentifierKey", &app->id) < 0 ||
                plist_util_get_string(value, "WIRApplicationNameKey", &app->name) < 0 ||
                plist_util_get_bool(value, "WIRIsApplicationProxyKey", &app->isProxy) < 0) {
                app_clear_(app);
                continue;
            }
            app->fd = fd;
            app->ssl = ssl;
            app->connectionID = connectionID;
            app_forward_get_listing_(app);
            ++index;
        } else {
            break;
        }
    }
    return 0;
}

int app_connected(int fd, SSL *ssl, const char *connectionID, plist_t app) {
    AppInfo_ *appInfo = app_new_();
    if (plist_util_get_string(app, "WIRApplicationIdentifierKey", &appInfo->id) < 0 ||
        plist_util_get_string(app, "WIRApplicationNameKey", &appInfo->name) < 0 ||
        plist_util_get_bool(app, "WIRIsApplicationProxyKey", &appInfo->isProxy) < 0) {
        app_delete_(appInfo);
        return -1;
    }
    appInfo->fd = fd;
    appInfo->ssl = ssl;
    appInfo->connectionID = connectionID;
    app_forward_get_listing_(appInfo);
    app_delete_(appInfo);
    return 0;
}
