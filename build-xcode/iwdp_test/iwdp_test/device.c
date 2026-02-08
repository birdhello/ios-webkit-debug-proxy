#include "device.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <openssl/ssl.h>
#include <usbmuxd.h>
#include <plist/plist.h>

#include "config.h"
#include "logger.h"
#include "iwdp.h"
#include "fd_util.h"
#include "message_util.h"
#include "app_util.h"
#include "map_util.h"
#include "plist_util.h"

static fd_set fd_set_;
static int max_fd_ = -1;
static Map *fd_map_ = NULL;

__attribute__((constructor)) static void device_constructor(void) {
    FD_ZERO(&fd_set_);
    fd_map_ = map_create();
}

__attribute__((destructor)) static void device_destructor(void) {
    FD_ZERO(&fd_set_);
    map_delete(fd_map_);
}

typedef struct {
    SSL *ssl;
    int fd;
    uint64_t deviceID;
    uint64_t productID;
    uint64_t locationID;
    char *connectionID;
    char *uniqueDeviceID;
    char *uuid;
    char *name;
    char *productVersionStr;
    int productVersionInt;

    void *recvData;
    size_t recvCapacity;
    size_t recvSize;
    void *recvRead;
} Device_;

static Device_ *device_new_(void) {
    return calloc(1, sizeof(Device_));
}

static void device_delete_(Device_ *device) {
    if (device->uuid) {
        free(device->uuid);
    }
    if (device->uniqueDeviceID) {
        free(device->uniqueDeviceID);
    }
    if (device->name) {
        free(device->name);
    }
    if (device->productVersionStr) {
        free(device->productVersionStr);
    }
    if (device->fd > 0) {
        close(device->fd);
    }
}

static int device_to_string_(Device_ *device, char **out) {
    return asprintf(out,
                    "deviceID: %" PRIu64
                    "\n\t productID: %" PRIu64
                    "\n\t locationID: %" PRIu64
                    "\n\t uniqueDeviceID: %s"
                    "\n\t connectionID: %s"
                    "\n\t uuid: %s"
                    "\n\t name: %s"
                    "\n\t version: %s(%d)"
                    "\n\t fd: %d"
                    "\n\t ssl: %p"
                    "\n"
                    , device->deviceID, device->productID, device->locationID,
                    device->uniqueDeviceID, device->connectionID, device->uuid
                    , device->name, device->productVersionStr, device->productVersionInt
                    , device->fd, device->ssl);
}

int device_append_recv_data(Device_ *deviceInfo, const char *rpc_bin, size_t rpc_len) {
    size_t needSize = deviceInfo->recvSize + rpc_len;
    if (needSize > deviceInfo->recvCapacity) {
        size_t capacity = deviceInfo->recvCapacity < 4? 4 : deviceInfo->recvCapacity;
        do {
            capacity *= 1.5;
        } while(capacity < needSize);
        size_t readSize = deviceInfo->recvRead - deviceInfo->recvData;
        char *new_begin = (char *) realloc(deviceInfo->recvData, capacity);
        if (!new_begin) {
            return -1;
        }
        deviceInfo->recvData = new_begin;
        deviceInfo->recvCapacity = capacity;
        deviceInfo->recvRead = deviceInfo->recvData + readSize;
    }

    memcpy(deviceInfo->recvData + deviceInfo->recvSize, rpc_bin, rpc_len);
    deviceInfo->recvSize += rpc_len;
    return 0;
}

void device_free_recv_data(Device_ *deviceInfo) {
    free(deviceInfo->recvData);
    deviceInfo->recvData = 0;
    deviceInfo->recvCapacity = 0;
    deviceInfo->recvSize = 0;
    deviceInfo->recvRead = 0;
}

void map_remove_by_fd_(int fd) {
    MapNode *iterator = map_find(fd_map_, map_create_key_by_int(fd));
    if (iterator) {
        Device_ *deviceInfo = map_node_get(iterator);
        if (deviceInfo->recvData) {
            free(deviceInfo->recvData);
        }
        free(deviceInfo);
        map_node_remove(fd_map_, iterator);
    }
}

Device_ *map_get_device_info_(int fd) {
    Device_ *ret = map_get(fd_map_, map_create_key_by_int(fd));
    return ret;
}

void map_set_ssl_(int fd, SSL *ssl) {
    Device_ *deviceInfo = map_get(fd_map_, map_create_key_by_int(fd));
    if (deviceInfo) {
        deviceInfo->ssl = ssl;
    }
}

SSL *map_get_ssl_(int fd) {
    Device_ *deviceInfo = map_get(fd_map_, map_create_key_by_int(fd));
    if (deviceInfo) {
        return deviceInfo->ssl;
    }
    return 0;
}

static const char *lockdownd_err_to_string(int ldret) {
  switch (ldret) {
    case LOCKDOWN_E_PASSWORD_PROTECTED:
      return "Please enter the passcode on the device, then try again.";
    case LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING:
      return "Please accept the trust dialog on the screen of device, then try again.";
    case LOCKDOWN_E_USER_DENIED_PAIRING:
      return "User denied the trust dialog. Re-plug device and try again.";
    case LOCKDOWN_E_INVALID_CONF:
    case LOCKDOWN_E_INVALID_HOST_ID:
      return "Device is not paired with this host. Re-plug device and try again.";
    default:
      return "Could not connect to lockdownd, error code: %d.";
  }
}

typedef struct {
  unsigned char *data;
  unsigned int size;
} key_data_t;

static int read_pair_record(const char *udid, plist_t *pair_record) {
    char* record_data = NULL;
    uint32_t record_size = 0;

    int res = usbmuxd_read_pair_record(udid, &record_data, &record_size);
    if (res < 0) {
        free(record_data);
        return -1;
    }

    *pair_record = NULL;
#if LIBPLIST_VERSION_MAJOR >= 2 && LIBPLIST_VERSION_MINOR >= 3
    plist_from_memory(record_data, record_size, pair_record, NULL);
#else
    plist_from_memory(record_data, record_size, pair_record);
#endif
    free(record_data);

    if (!*pair_record) {
        return -1;
    }

    return 0;
}

static int pair_record_get_item_as_key_data(plist_t pair_record, const char* name, key_data_t *value) {
    char* buffer = NULL;
    uint64_t length = 0;
    plist_t node = plist_dict_get_item(pair_record, name);

    if (node && plist_get_node_type(node) == PLIST_DATA) {
        plist_get_data_val(node, &buffer, &length);
        value->data = (unsigned char*) malloc(length + 1);
        memcpy(value->data, buffer, length);
        value->data[length] = '\0';
        value->size = (int) length + 1;
        free(buffer);
        return 0;
    }

    return -1;
}

static int idevice_ext_connection_enable_ssl(const char *uuid, int fd, SSL **to_session) {
  plist_t pair_record = NULL;
  if (read_pair_record(uuid, &pair_record)) {
    fprintf(stderr, "Failed to read pair record\n");
    return -1;
  }

  key_data_t root_cert = { NULL, 0 };
  key_data_t root_privkey = { NULL, 0 };
  pair_record_get_item_as_key_data(pair_record, "RootCertificate", &root_cert);
  pair_record_get_item_as_key_data(pair_record, "RootPrivateKey", &root_privkey);
  plist_free(pair_record);

  BIO *ssl_bio = BIO_new(BIO_s_socket());
  if (!ssl_bio) {
    fprintf(stderr, "Could not create SSL bio\n");
    return -1;
  }

  BIO_set_fd(ssl_bio, fd, BIO_NOCLOSE);
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Could not create SSL context\n");
    BIO_free(ssl_bio);
  }

  SSL_CTX_set_security_level(ssl_ctx, 0);
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);

  BIO* membp;
  X509* rootCert = NULL;
  membp = BIO_new_mem_buf(root_cert.data, root_cert.size);
  PEM_read_bio_X509(membp, &rootCert, NULL, NULL);
  BIO_free(membp);
  SSL_CTX_use_certificate(ssl_ctx, rootCert);
  X509_free(rootCert);
  free(root_cert.data);

  EVP_PKEY* rootPrivKey = NULL;
  membp = BIO_new_mem_buf(root_privkey.data, root_privkey.size);
  PEM_read_bio_PrivateKey(membp, &rootPrivKey, NULL, NULL);
  BIO_free(membp);
  SSL_CTX_use_PrivateKey(ssl_ctx, rootPrivKey);
  EVP_PKEY_free(rootPrivKey);

  free(root_privkey.data);

  SSL *ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    fprintf(stderr, "Could not create SSL object\n");
    BIO_free(ssl_bio);
    SSL_CTX_free(ssl_ctx);
    return -1;
  }

  SSL_set_connect_state(ssl);
  SSL_set_verify(ssl, 0, NULL);
  SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_set_bio(ssl, ssl_bio, ssl_bio);

  int ssl_error = 0;
  while (1) {
    ssl_error = SSL_get_error(ssl, SSL_do_handshake(ssl));
    if (ssl_error == 0 || ssl_error != SSL_ERROR_WANT_READ) {
      break;
    }
#ifdef WIN32
    Sleep(100);
#else
    struct timespec ts = { 0, 100000000 };
    nanosleep(&ts, NULL);
#endif
  }

  if (ssl_error != 0) {
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    return ssl_error;
  }

  *to_session = ssl;
  return 0;
}


#include <uuid/uuid.h>

int rpc_new_uuid(char **to_uuid) {
    if (!to_uuid) {
        return -1;
    }
    *to_uuid = (char *) malloc(37);
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse_upper(uuid, *to_uuid);
    return true;
}

plist_t rpc_new_args(const char *connection_id) {
    plist_t ret = plist_new_dict();
    if (connection_id) {
        plist_dict_set_item(ret, "WIRConnectionIdentifierKey",
                            plist_new_string(connection_id));
    }
    return ret;
}

static int rpc_send_msg(int fd, const char *selector, plist_t args) {
    if (!selector || !args) {
        return -1;
    }
    plist_t rpc_dict = plist_new_dict();
    plist_dict_set_item(rpc_dict, "__selector",
                        plist_new_string(selector));
    plist_dict_set_item(rpc_dict, "__argument", plist_copy(args));

    int ret;
    SSL *ssl = map_get_ssl_(fd);
    if (ssl) {
        ret = plist_util_send_by_ssl(ssl, rpc_dict);
    } else {
        ret = plist_util_send_by_fd(fd, rpc_dict);
    }
    plist_free(rpc_dict);
    return ret;
}


int rpc_send_reportIdentifier(int fd, const char *connection_id) {
  if (!connection_id) {
    return -1;
  }
  const char *selector = "_rpc_reportIdentifier:";
  plist_t args = rpc_new_args(connection_id);
  int ret = rpc_send_msg(fd, selector, args);
  plist_free(args);
  return ret;
}

int device_on_attached(plist_t props) {
    Device_ *device = (Device_ *) calloc(1, sizeof(Device_));

    idevice_t phone = NULL;
    lockdownd_client_t client = NULL;
    idevice_connection_t connection = NULL;
    int ret = 0;
    if (plist_util_get_uint64(props, "DeviceID", &device->deviceID) < 0) {
        LogE("invalid DeviceID")
        ret = -1;
        goto error_;
    }
    if (plist_util_get_uint64(props, "ProductID", &device->productID) < 0) {
        LogE("invalid ProductID")
        ret = -1;
        goto error_;
    }
    if (plist_util_get_string(props, "SerialNumber", &device->uuid) < 0) {
        LogE("invalid SerialNumber")
        ret = -1;
        goto error_;
    }
    if (strlen(device->uuid) == 24) {
        char *new_uuid = malloc(sizeof(char) * 26);

        memcpy(new_uuid, device->uuid, 8);
        memcpy(new_uuid + 9, device->uuid + 8, 17);
        new_uuid[8] = '-';

        free(device->uuid);
        device->uuid = new_uuid;
    }
    if (plist_util_get_uint64(props, "LocationID", &device->locationID) < 0) {
        LogE("invalid LocationID")
        ret = -1;
        goto error_;
    }

    // get phone
    idevice_error_t deviceError = idevice_new_with_options(&phone,
                                                           device->uuid,
                                                           IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK);
    if (deviceError != IDEVICE_E_SUCCESS) {
        LogE("idevice_new_with_options error code: %d", deviceError)
        ret = -1;
        goto error_;
    }

    // connect to lockdownd
    lockdownd_error_t ldret = lockdownd_client_new_with_handshake(phone, &client, "ios_webkit_debug_proxy");
    if (ldret != LOCKDOWN_E_SUCCESS) {
        LogE("lockdownd_client_new_with_handshake error code: %d", ldret)
        ret = -1;
        goto error_;
    }
    plist_t node = NULL;
    // get device info
    ldret = lockdownd_get_value(client, NULL, "UniqueDeviceID", &node);
    if (ldret == LOCKDOWN_E_SUCCESS) {
        plist_get_string_val(node, &device->uniqueDeviceID);
        plist_free(node);
    }
    ldret = lockdownd_get_value(client, NULL, "DeviceName", &node);
    if (ldret == LOCKDOWN_E_SUCCESS) {
        plist_get_string_val(node, &device->name);
        plist_free(node);
    }
    ldret = lockdownd_get_value(client, NULL, "ProductVersion", &node);
    if (ldret == LOCKDOWN_E_SUCCESS) {
        int vers[3] = {0, 0, 0};
        plist_get_string_val(node, &device->productVersionStr);
        if (device->productVersionStr &&
            sscanf(device->productVersionStr, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
            device->productVersionInt = ((vers[0] & 0xFF) << 16) | ((vers[1] & 0xFF) << 8) | (vers[2] & 0xFF);
        }
        plist_free(node);
    }

    lockdownd_service_descriptor_t service = NULL;
    // start webinspector, get port
    ldret = lockdownd_start_service(client, "com.apple.webinspector", &service);
    if (ldret != LOCKDOWN_E_SUCCESS || !service || !service->port) {
        LogE("service(com.apple.webinspector) start error code:%d", ldret)
        ret = -1;
        goto error_;
    }
    // connect to webinspector
    deviceError = idevice_connect(phone, service->port, &connection);
    if (deviceError != IDEVICE_E_SUCCESS) {
        LogE("device connect service(com.apple.webinspector) error code:%d", deviceError)
        ret = -1;
        goto error_;
    }
    // extract the connection fd
    if (idevice_connection_get_fd(connection, &device->fd)) {
        LogE("Unable to get connection file descriptor.");
        ret = -1;
        goto error_;
    }

    // enable ssl
    if (service->ssl_enabled == 1) {
        int ssl_ret = idevice_ext_connection_enable_ssl(device->uuid,
                                                        device->fd,
                                                        &device->ssl);
        if (ssl_ret) {
            LogE("SSL connection failed! Error code: %d", ssl_ret);
            ret = -1;
            goto error_;
        }
    }

    if (fd_set_timeout(device->fd, -1) < 0) {
        LogE("fd_set_timeout fail");
        ret = -1;
        goto error_;
    }
    // start inspector
    rpc_new_uuid(&device->connectionID);

    char *deviceInfoStr;
    if (device_to_string_(device, &deviceInfoStr) > 0) {
        LogD("device: \n\t%s", deviceInfoStr)
        free(deviceInfoStr);
    }
    FD_SET(device->fd, &fd_set_);
    if (max_fd_ < device->fd) {
        max_fd_ = device->fd;
    }
    MapKey *k = map_create_key_by_int(device->fd);
    map_set(fd_map_, k, device);

    if (rpc_send_reportIdentifier(device->fd, device->connectionID) < 0) {
        LogE("rpc_send_reportIdentifier fail");
        ret = -1;
        goto error_;
    }
    goto success_;

error_:
    device_delete_(device);

success_:
    // don't call usbmuxd_disconnect(fd)!
    // idevice_disconnect(connection);
    if (connection) {
        free(connection);
    }
    if (client) {
        lockdownd_client_free(client);
    }
    if (phone) {
        idevice_free(phone);
    }
    return ret;
}

// some arbitrarly limit, to catch bad packets
#define MAX_BODY_LENGTH 1<<26

int wi_parse_length(const char *buf, size_t *to_length) {
    if (!buf || !to_length) {
        return -1;
    }
    *to_length = (
                  ((((unsigned char) buf[0]) & 0xFF) << 24) |
                  ((((unsigned char) buf[1]) & 0xFF) << 16) |
                  ((((unsigned char) buf[2]) & 0xFF) << 8) |
                  (((unsigned char) buf[3]) & 0xFF));
    if (MAX_BODY_LENGTH > 0 && *to_length > MAX_BODY_LENGTH) {
#define TO_CHAR(c) ((c) >= ' ' && (c) < '~' ? (c) : '.')

        printf("%s:%d %s Invalid packet header 0x%x%x%x%x == %c%c%c%c == %zd\n",
               __FILE__, __LINE__, __FUNCTION__,
               buf[0], buf[1], buf[2], buf[3],
               TO_CHAR(buf[0]), TO_CHAR(buf[1]),
               TO_CHAR(buf[2]), TO_CHAR(buf[3]),
               *to_length);
        return -1;
    }
    return 0;
}

static int device_parse_plist(Device_ *deviceInfo,
                              const char *from_buf, size_t length,
                              plist_t *to_rpc_dict,
                              bool *to_is_partial) {
    *to_is_partial = false;
    *to_rpc_dict = NULL;

    // TODO
//    bool is_sim = !strcmp(uuid, "SIMULATOR");
//    partials_supported = !is_sim;
    bool partials_supported = false;
    if (!partials_supported) {
        plist_from_bin(from_buf, (uint32_t) length, to_rpc_dict);
    } else {
        plist_t wi_dict = NULL;
        plist_from_bin(from_buf, (uint32_t) length, &wi_dict);
        if (!wi_dict) {
            return -1;
        }
        plist_t wi_rpc = plist_dict_get_item(wi_dict, "WIRFinalMessageKey");
        if (!wi_rpc) {
            wi_rpc = plist_dict_get_item(wi_dict, "WIRPartialMessageKey");
            if (!wi_rpc) {
                return -1;
            }
            *to_is_partial = true;
        }

        uint64_t rpc_len = 0;
        char *rpc_bin = NULL;
        plist_get_data_val(wi_rpc, &rpc_bin, &rpc_len);
        plist_free(wi_dict); // also frees wi_rpc
        if (!rpc_bin) {
            return -1;
        }

        if (*to_is_partial || deviceInfo->recvSize) {
            int result = device_append_recv_data(deviceInfo, rpc_bin, rpc_len);
            free(rpc_bin);
            if (result < 0) {
                return result;
            }
            if (*to_is_partial) {
                return 0;
            }
        }

        if (deviceInfo->recvSize) {
            plist_from_bin(deviceInfo->recvData, (uint32_t) deviceInfo->recvSize, to_rpc_dict);
            device_free_recv_data(deviceInfo);
        } else {
            plist_from_bin(rpc_bin, (uint32_t) rpc_len, to_rpc_dict);
            free(rpc_bin);
        }
    }

    return (*to_rpc_dict ? 0 : -1);
}

static int device_on_packet_(Device_ *deviceInfo, plist_t rpc_dict) {
    char *selector = NULL;
    plist_get_string_val(plist_dict_get_item(rpc_dict, "__selector"), &selector);

    if (!selector) {
        return -1;
    }
    plist_t args = plist_dict_get_item(rpc_dict, "__argument");


    if (!strcmp(selector, "_rpc_reportSetup:")) {
        //      if (!rpc_recv_reportSetup(self, args)) {
        //        return RPC_SUCCESS;
        //      }
        return 0;
    } else if (!strcmp(selector, "_rpc_reportConnectedApplicationList:")) {
        plist_t list = plist_dict_get_item(args, "WIRApplicationDictionaryKey");
        return app_list_update(deviceInfo->fd, deviceInfo->ssl, deviceInfo->connectionID, list);
    } else if (!strcmp(selector, "_rpc_applicationConnected:")) {
        return app_connected(deviceInfo->fd, deviceInfo->ssl, deviceInfo->connectionID, args);
    } else if (!strcmp(selector, "_rpc_applicationDisconnected:")) {
        //      if (!rpc_recv_applicationDisconnected(self, args)) {
        //        return RPC_SUCCESS;
        //      }
        return 0;
    } else if (!strcmp(selector, "_rpc_applicationSentListing:")) {
        char *appID;
        if (plist_util_get_string(args, "WIRApplicationIdentifierKey", &appID) < 0) {
            return -1;
        }
        App *app = app_get(appID);
        if (!app) {
            return -1;
        }
        plist_t pageList;
        if (plist_util_get_dict(args, "WIRListingKey", &pageList) < 0) {
            return -1;
        }
        return app_on_sent_listing(app, args);
    } else if (!strcmp(selector, "_rpc_applicationSentData:")) {
        //      if (!rpc_recv_applicationSentData(self, args)) {
        //        return RPC_SUCCESS;
        //      }

        return 0;
    } else if (!strcmp(selector, "_rpc_applicationUpdated:")) {
        //      if (!rpc_recv_applicationUpdated(self, args)) {
        //        return RPC_SUCCESS;
        //      }
        return 0;
    } else if (!strcmp(selector, "_rpc_reportConnectedDriverList:") || !strcmp(selector, "_rpc_reportCurrentState:")) {

        return 0;
    } else {
        printf("%s:%d %s| unsupported selector: %s\n",
               __FILE__, __LINE__, __FUNCTION__,
               selector);
        return -1;
    }
}

static int device_on_recv_packet_(void *userData, const char *packet, size_t length) {
    Device_ *deviceInfo = (Device_ *) userData;
    size_t body_length = 0;
    plist_t rpc_dict = NULL;
    bool is_partial = false;
    if (!packet || length < 4 || wi_parse_length(packet, &body_length) ||
        //TODO (body_length != length - 4) ||
        device_parse_plist(deviceInfo, packet + 4, body_length, &rpc_dict, &is_partial) < 0) {
        // invalid packet
        char *text = NULL;
        if (body_length != length - 4) {
            if (asprintf(&text, "size %zd != %zd - 4", body_length, length) < 0) {
                printf("%s:%d %s| asprintf failed\n",
                       __FILE__, __LINE__, __FUNCTION__);
                return -1;
            }
        } else {
            //        cb_asprint(&text, packet, length, 80, 50);
        }
        printf("%s:%d %s| Invalid packet:\n%s\n",
               __FILE__, __LINE__, __FUNCTION__,
               text);
        free(text);
        return -1;
    }

    char *json_data = NULL;
    uint32_t json_length = 0;
    if (plist_to_json(rpc_dict, &json_data, &json_length, true) == PLIST_ERR_SUCCESS) {
        LogD("json: \n%s", json_data);
        free(json_data);
    } else if (plist_to_openstep(rpc_dict, &json_data, &json_length, true) == PLIST_ERR_SUCCESS) {
        LogD("openstep: \n%s", json_data);
        free(json_data);
    } else if (plist_to_xml(rpc_dict, &json_data, &json_length) == PLIST_ERR_SUCCESS) {
        LogD("xml: \n%s", json_data);
        free(json_data);
    } else {
        LogD("data: \n%.*s", (int) body_length, packet + 4)
    }

    if (is_partial) {
        return 0;
    }
    int ret = device_on_packet_(deviceInfo, rpc_dict);
    plist_free(rpc_dict);
    return ret;
}

static int device_on_recv_(void *userData, const char *packet, size_t length) {
    Device_ *deviceInfo = (Device_ *) userData;
    const char *in_head;
    size_t in_length;
    if (deviceInfo->recvSize) {
        device_append_recv_data(deviceInfo, packet, length);
        in_head = deviceInfo->recvRead;
        in_length = deviceInfo->recvSize - (deviceInfo->recvRead - deviceInfo->recvData);
    } else {
        in_head = packet;
        in_length = length;
    }
    const char *in_tail = in_head + in_length;

    int ret;
    bool has_length = false;
    size_t body_length = 0;
    while (1) {
        if (!has_length && in_length >= 4) {
            // can read body_length now
            size_t len;
            ret = wi_parse_length(in_head, &len);
            if (ret < 0) {
                in_head += 4;
                break;
            }
            body_length = len;
            has_length = true;
            // don't advance in_head yet
        } else if (has_length && in_length >= body_length + 4) {
            // can read body now
            printf("%s:%d %s| have: %zu, use: %zu\n",
                   __FILE__, __LINE__, __FUNCTION__,
                   in_length, body_length + 4);
            ret = device_on_recv_packet_(deviceInfo, in_head, body_length + 4);
            in_head += body_length + 4;
            in_length -= body_length + 4;
            has_length = false;
            body_length = 0;
            if (ret) {
                break;
            }
        } else {
            // need more input
            ret = 0;
            break;
        }
    }

    if (in_head == in_tail) {
        if (deviceInfo->recvSize) {
            device_free_recv_data(deviceInfo);
        }
    } else {
        if (deviceInfo->recvSize) {
            deviceInfo->recvRead = (void *) in_head;
        } else {
            device_append_recv_data(deviceInfo, in_head, in_length);
        }
    }
    return 0;
}

static int device_on_recv_ready_(int fd) {
    Device_ *deviceInfo = map_get_device_info_(fd);
    if (deviceInfo->ssl) {
        ssl_recv(deviceInfo->ssl, device_on_recv_, deviceInfo);
    } else {
        fd_recv(fd, device_on_recv_, deviceInfo);
    }
    return 0;
}

int device_on_loop(void) {
    int result = message_select(fd_set_, max_fd_, device_on_recv_ready_);
    if (result < 0) {
        return result;
    }
    return result;
}
