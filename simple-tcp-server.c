#include "simple-tcp-server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

tcp_server_ctx_t* tcp_server_new()
{
    tcp_server_ctx_t* ctx = (tcp_server_ctx_t*) calloc(1, sizeof(tcp_server_ctx_t));
    ctx->port = 0;
    ctx->listen_socket = 0;
    ctx->backlog = 5;
    ctx->client_sockets = NULL;
    return ctx;
}

void tcp_server_free(const tcp_server_ctx_t* ctx)
{
    close(ctx->listen_socket);

    socketlist_t* tmp = ctx->client_sockets;
    while(tmp != NULL){
        close(tmp->socket);
        tmp = tmp->next;
    }
    socketlist_free(ctx->client_sockets);
}

void tcp_server_prepare_listen(tcp_server_ctx_t* ctx)
{
    if((ctx->listen_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    int on = 1;
    if(setsockopt(ctx->listen_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1){
        perror("setsockopt error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(ctx->listen_socket, (struct sockaddr*) &addr, sizeof(addr)) == -1){
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    if(listen(ctx->listen_socket, ctx->backlog) != 0){
        perror("listen error");
    }
}

void accept_socket(tcp_server_ctx_t* ctx)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sd = accept(ctx->listen_socket, (struct sockaddr *)&client_addr, &client_len);
    if(client_sd < 0){
        perror("accept error");
        exit(EXIT_FAILURE);
    }

    /* SET NONBLOCK */
    int flags;
    flags = fcntl(client_sd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL) failed");
        exit(EXIT_FAILURE);
    }
    if (fcntl(client_sd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL) failed");
        exit(EXIT_FAILURE);
    }

    ctx->client_sockets = socketlist_append(ctx->client_sockets, client_sd);
}
