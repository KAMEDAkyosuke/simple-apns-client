#ifndef SIMPLE_TCP_SERVER_H
#define SIMPLE_TCP_SERVER_H

#include "socketlist.h"

typedef struct {
    int port;
    int listen_socket;
    int backlog;
    socketlist_t* client_sockets;
} tcp_server_ctx_t;

tcp_server_ctx_t* tcp_server_new();
void tcp_server_free(const tcp_server_ctx_t* ctx);

void tcp_server_prepare_listen(tcp_server_ctx_t* ctx);
void accept_socket(tcp_server_ctx_t* ctx);

#endif
