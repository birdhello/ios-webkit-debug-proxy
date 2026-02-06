#include "device.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <malloc/_malloc.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <openssl/ssl.h>
#include <usbmuxd.h>
#include <plist/plist.h>

#include "config.h"
#include "iwdp.h"
#include "fd_util.h"
#include "message_util.h"
#include "application_util.h"
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
    char *connectionID;
    int fd;

    void *recvData;
    size_t recvCapacity;
    size_t recvSize;
    void *recvRead;
} DeviceInfo_;

int device_append_recv_data(DeviceInfo_ *deviceInfo, const char *rpc_bin, size_t rpc_len) {
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

void device_free_recv_data(DeviceInfo_ *deviceInfo) {
    free(deviceInfo->recvData);
    deviceInfo->recvData = 0;
    deviceInfo->recvCapacity = 0;
    deviceInfo->recvSize = 0;
    deviceInfo->recvRead = 0;
}

DeviceInfo_ *map_set_by_fd_(int fd) {
    DeviceInfo_ *deviceInfo = malloc(sizeof(DeviceInfo_));
    memset(deviceInfo, 0, sizeof(DeviceInfo_));
    map_set(fd_map_, fd, deviceInfo);
    return deviceInfo;
}

void map_remove_by_fd_(int fd) {
    MapNode *iterator = map_find(fd_map_, fd);
    if (iterator) {
        DeviceInfo_ *deviceInfo = map_node_get(iterator);
        if (deviceInfo->recvData) {
            free(deviceInfo->recvData);
        }
        free(deviceInfo);
        map_node_remove(fd_map_, iterator);
    }
}

DeviceInfo_ *map_get_device_info_(int fd) {
    return map_get(fd_map_, fd);
}

void map_set_ssl_(int fd, SSL *ssl) {
    DeviceInfo_ *deviceInfo = map_get(fd_map_, fd);
    if (deviceInfo) {
        deviceInfo->ssl = ssl;
    }
}

SSL *map_get_ssl_(int fd) {
    DeviceInfo_ *deviceInfo = map_get(fd_map_, fd);
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
        value->data = (unsigned char*)malloc(length+1);
        memcpy(value->data, buffer, length);
        value->data[length] = '\0';
        value->size = (int) length + 1;
        free(buffer);
        return 0;
    }

    return -1;
}

static int idevice_ext_connection_enable_ssl(const char *device_id, int fd, SSL **to_session) {
  plist_t pair_record = NULL;
  if (read_pair_record(device_id, &pair_record)) {
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
    *to_uuid = (char *)malloc(37);
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

int device_attach(const char *device_id, int device_num) {
    printf("%s:%d %s| device_id: %s, device_num: %d\n",
           __FILE__, __LINE__, __FUNCTION__,
           device_id, device_num);
    if (!device_id) {
        printf("Null device_id\n");
        return -1;
    }
    bool fail = true;

    idevice_t phone = NULL;
    lockdownd_client_t client = NULL;
    idevice_connection_t connection = NULL;
    int fd = -1;

    // get phone
    if (idevice_new_with_options(&phone, device_id, IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK)) {
      fprintf(stderr, "No device found, is it plugged in?\n");
      goto leave_cleanup;
    }

    // connect to lockdownd
    lockdownd_error_t ldret = lockdownd_client_new_with_handshake(phone, &client, "ios_webkit_debug_proxy");
    if (ldret != LOCKDOWN_E_SUCCESS) {
      fprintf(stderr, "%s\n", lockdownd_err_to_string(ldret));
      goto leave_cleanup;
    }

    plist_t node = NULL;
    // get device info
    char *uniqueDeviceID = NULL;
    if (!lockdownd_get_value(client, NULL, "UniqueDeviceID", &node)) {
      plist_get_string_val(node, &uniqueDeviceID);
      plist_free(node);
      node = NULL;
    }
    printf("%s:%d %s| UniqueDeviceID: %s\n",
           __FILE__, __LINE__, __FUNCTION__,
           uniqueDeviceID);
    char *deviceName = NULL;
    if (!lockdownd_get_value(client, NULL, "DeviceName", &node)) {
      plist_get_string_val(node, &deviceName);
      plist_free(node);
      node = NULL;
    }
    printf("%s:%d %s| DeviceName: %s\n",
           __FILE__, __LINE__, __FUNCTION__,
           deviceName);
    int productVersion = 0;
    if (!lockdownd_get_value(client, NULL, "ProductVersion", &node)) {
        int vers[3] = {0, 0, 0};
        char *s_version = NULL;
        plist_get_string_val(node, &s_version);
        if (s_version && sscanf(s_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
            productVersion = ((vers[0] & 0xFF) << 16) | ((vers[1] & 0xFF) << 8) | (vers[2] & 0xFF);
            printf("%s:%d %s| ProductVersion: %s to int: %d\n",
                   __FILE__, __LINE__, __FUNCTION__,
                   s_version, productVersion);
        } else {
            productVersion = 0;
        }
        free(s_version);
        plist_free(node);
    }

    lockdownd_service_descriptor_t service = NULL;
    // start webinspector, get port
    ldret = lockdownd_start_service(client, "com.apple.webinspector", &service);
    if (ldret != LOCKDOWN_E_SUCCESS || !service || !service->port) {
      fprintf(stderr, "Could not start com.apple.webinspector! Error code: %d\n", ldret);
      goto leave_cleanup;
    }
    printf("%s:%d %s| webinspector port: %" PRIu16", ssl_enabled: %" PRIu8", identifier: %s\n",
           __FILE__, __LINE__, __FUNCTION__,
           service->port, service->ssl_enabled, service->identifier);

    // connect to webinspector
    if (idevice_connect(phone, service->port, &connection)) {
      perror("idevice_connect failed!");
      goto leave_cleanup;
    }

    if (client) {
      // not needed anymore
      lockdownd_client_free(client);
      client = NULL;
    }

    // extract the connection fd
    if (idevice_connection_get_fd(connection, &fd)) {
      perror("Unable to get connection file descriptor.");
      goto leave_cleanup;
    }
    printf("%s:%d %s| fd: %d\n",
           __FILE__, __LINE__, __FUNCTION__,
           fd);

    SSL *ssl = NULL;
    // enable ssl
    if (service->ssl_enabled == 1) {
      int ssl_ret = idevice_ext_connection_enable_ssl(device_id, fd, &ssl);
      if (ssl_ret) {
        fprintf(stderr, "SSL connection failed! Error code: %d\n", ssl_ret);
        goto leave_cleanup;
      }
    }
    printf("%s:%d %s| ssl: %p\n",
           __FILE__, __LINE__, __FUNCTION__,
           ssl);

    if (fd_set_timeout(fd, -1) < 0) {
        goto leave_cleanup;
    }
    fail = false;
    
    FD_SET(fd, &fd_set_);
    if (max_fd_ < fd) {
        max_fd_ = fd;
    }
    // start inspector
    char *connectionID = NULL;
    rpc_new_uuid(&connectionID);

    DeviceInfo_ *deviceInfo = map_set_by_fd_(fd);
    deviceInfo->connectionID = connectionID;
    deviceInfo->ssl = ssl;
    deviceInfo->fd = fd;

    char *deviceInfoStr = device_info_to_string(deviceInfo);
    printf("%s:%d %s| %s\n",
           __FILE__, __LINE__, __FUNCTION__,
           deviceInfoStr);
    free(deviceInfoStr);


    if (rpc_send_reportIdentifier(fd, connectionID) < 0) {
        // TODO
    }

leave_cleanup:
    if (fail && fd > 0) {
        close(fd);
    }
    // don't call usbmuxd_disconnect(fd)!
    //idevice_disconnect(connection);
    free(connection);
    lockdownd_client_free(client);
    idevice_free(phone);
    return fd;
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

static int device_parse_plist(DeviceInfo_ *deviceInfo,
                              const char *from_buf, size_t length,
                              plist_t *to_rpc_dict,
                              bool *to_is_partial) {
    *to_is_partial = false;
    *to_rpc_dict = NULL;

    // TODO
//    bool is_sim = !strcmp(device_id, "SIMULATOR");
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

static int device_on_packet_(DeviceInfo_ *deviceInfo, plist_t rpc_dict) {
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
        //      if (!rpc_recv_applicationSentListing(self, args)) {
        //        return RPC_SUCCESS;
        //      }

        return 0;
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
    DeviceInfo_ *deviceInfo = (DeviceInfo_ *) userData;
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
    plist_err_t plistError = plist_to_json(rpc_dict, &json_data, &json_length, true);
    if (plistError == PLIST_ERR_SUCCESS) {
        printf("%s:%d %s| %s\n", __FILE__, __LINE__, __FUNCTION__, json_data);
        free(json_data);
    }

    if (is_partial) {
        return 0;
    }
    int ret = device_on_packet_(deviceInfo, rpc_dict);
    plist_free(rpc_dict);
    return ret;
}

static int device_on_recv_(void *userData, const char *packet, size_t length) {
    DeviceInfo_ *deviceInfo = (DeviceInfo_ *) userData;
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
    DeviceInfo_ *deviceInfo = map_get_device_info_(fd);
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
