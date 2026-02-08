#include "plist_util.h"

#include <stdlib.h>
#include <string.h>

#include "message_util.h"
#include "logger.h"

int plist_util_get_bool(plist_t plist, const char *key, bool *dest) {
    plist_t item = plist_dict_get_item(plist, key);
    plist_type plistType = plist_get_node_type(item);
    if (plistType == PLIST_BOOLEAN) {
        uint8_t value = 0;
        plist_get_bool_val(item, &value);
        *dest = value ? true : false;
        return 0;
    } else {
        LogE("key: %s, type: %d != %d(PLIST_BOOLEAN)",
             key, plistType, PLIST_BOOLEAN);
    }
    return -1;
}

int plist_util_get_uint64(plist_t plist, const char *key, uint64_t *dest) {
    plist_t item = plist_dict_get_item(plist, key);
    plist_type plistType = plist_get_node_type(item);
    if (plistType != PLIST_INT) {
        LogE("key: %s, type: %d != %d(PLIST_INT)",
             key, plistType, PLIST_INT);
        return -1;
    }
    plist_get_uint_val(item, dest);
    return 0;
}

int plist_util_get_string(plist_t plist, const char *key, char **dest) {
    plist_t item = plist_dict_get_item(plist, key);
    plist_type plistType = plist_get_node_type(item);
    if (plistType == PLIST_STRING) {
        plist_get_string_val(item, dest);
        return 0;
    } else {
        LogE("key: %s, type: %d != %d(PLIST_STRING)",
             key, plistType, PLIST_STRING);
    }
    return -1;
}

int plist_util_get_dict(plist_t plist, const char *key, plist_t *dest) {
    plist_t item = plist_dict_get_item(plist, key);
    plist_type plistType = plist_get_node_type(item);
    if (plistType == PLIST_DICT) {
        *dest = item;
        return 0;
    } else {
        LogE("key: %s, type: %d != %d(PLIST_DICT)",
             key, plistType, PLIST_DICT);
    }
    return -1;
}

static int plist_send_to_bin_(plist_t plist, char **out, size_t *out_len) {
    char *json_data = NULL;
    uint32_t json_length = 0;
    if (plist_to_json(plist, &json_data, &json_length, true) == PLIST_ERR_SUCCESS) {
        printf("%s:%d %s| %s\n", __FILE__, __LINE__, __FUNCTION__, json_data);
        free(json_data);
    }

    char *plist_bin = NULL;
    uint32_t plist_bin_length = 0;
    plist_to_bin(plist, &plist_bin, &plist_bin_length);

    size_t length = plist_bin_length + 4;
    char *binary = (char *) malloc(length);
    if (!binary) {
        return -1;
    }
    *out = binary;
    *out_len = length;

    char *binary_tail = binary;
    // write big-endian int
    *binary_tail++ = ((plist_bin_length >> 24) & 0xFF);
    *binary_tail++ = ((plist_bin_length >> 16) & 0xFF);
    *binary_tail++ = ((plist_bin_length >> 8) & 0xFF);
    *binary_tail++ = (plist_bin_length & 0xFF);
    if (plist_bin) {
        memcpy(binary_tail, plist_bin, plist_bin_length);
    }
    return 0;
}

int plist_util_send_by_fd(int fd, plist_t plist) {
    char *binary;
    size_t length;
    int ret = plist_send_to_bin_(plist, &binary, &length);
    if (ret < 0) {
        return ret;
    }
    ret = fd_send(fd, binary, length);
    free(binary);
    return ret;
}

int plist_util_send_by_ssl(SSL *ssl, plist_t plist) {
    char *binary;
    size_t length;
    int ret = plist_send_to_bin_(plist, &binary, &length);
    if (ret < 0) {
        return ret;
    }
    ret = ssl_send(ssl, binary, length);
    free(binary);
    return ret;
}
