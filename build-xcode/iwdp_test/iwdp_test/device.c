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
