#pragma once

#include <sys/select.h>
#include <stddef.h>
#include <stdio.h>

typedef int(*message_on_recv)(int fd);
typedef int(*message_on_send)(void);
typedef int(*message_on_fail)(void);

typedef int(*data_on_recv)(const char *data, size_t length);

typedef struct ssl_st SSL;

int fd_send(int fd, const char *data, size_t length);

int ssl_send(SSL *ssl, const char *data, size_t length);

int fd_recv(int fd, data_on_recv on_recv);

int ssl_recv(SSL *ssl, data_on_recv on_recv);

int message_select(fd_set fdSet, int max_fd, message_on_recv on_recv);
