#pragma once

int iwdp_connect(const char *device_id,
                 char **to_device_id,
                 char **to_device_name,
                 int *to_device_os_version,
                 void **to_ssl_session,
                 int recv_timeout);

int iwdp_listen(const char *device_id);
