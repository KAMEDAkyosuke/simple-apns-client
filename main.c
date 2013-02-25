#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <sys/select.h>
#include <unistd.h>
#include <inttypes.h>

#include <getopt.h>

#include "simple-apns-client.h"
#include "simple-tcp-server.h"

int main(int argc, char** argv)
{
    bool use_production = true;
    char* certificate_chain_file_path = NULL;
    char* private_key_file_path = NULL;
    int tcp_server_port = 8080;
    int tcp_server_bocklog = 5;

    int opt;
    while ((opt = getopt(argc, argv, "dc:k:p:")) != -1) {
        switch (opt) {
        case 'd':
            use_production = false;
            break;
        case 'c':
            certificate_chain_file_path = optarg;
            break;
        case 'k':
            private_key_file_path = optarg;
            break;
        case 'p':
            tcp_server_port = strtoimax(optarg, NULL, 10);
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-p use_production] [-c] cer file path [-k] key file path [-p] tcp server port\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }    

    apns_client_ctx_t* apns_ctx = apns_client_new();
    
    apns_ctx->host_name = use_production ? "gateway.push.apple.com" : "gateway.sandbox.push.apple.com";
    apns_ctx->port = 2195;
    apns_ctx->certificate_chain_file_path = certificate_chain_file_path;
    apns_ctx->private_key_file_path = private_key_file_path;

    if(apns_client_connect(apns_ctx) != APNS_CLIENT_RETURN_OK){
        fprintf(stderr, "ERROR : %s\n", apns_ctx->error_message);
        exit(EXIT_FAILURE);
    }

    tcp_server_ctx_t* tcp_ctx = tcp_server_new();
    tcp_ctx->port = tcp_server_port;
    tcp_ctx->backlog = tcp_server_bocklog;
    tcp_server_prepare_listen(tcp_ctx);
    
    fd_set readfds;
    int r;
    int max;
    while(true){
        FD_ZERO(&readfds);

        {// SET READFDS
            FD_SET(tcp_ctx->listen_socket, &readfds);
            max = tcp_ctx->listen_socket;
            
            socketlist_t* cursor = tcp_ctx->client_sockets;
            while(cursor != NULL){
                FD_SET(cursor->socket, &readfds);
                max = max > cursor->socket ? max : cursor->socket;
                cursor = cursor->next;
            }
        }

        r = select(max + 1, &readfds, NULL, NULL, NULL);

        if(r == -1){
            perror("select error");
            exit(EXIT_FAILURE);
        }
        else{
            socketlist_t* cursor = tcp_ctx->client_sockets;
            while(cursor != NULL){
                if(FD_ISSET(cursor->socket, &readfds)){
                    // buffer = 32(TOKEN) + 2(PAYLOAD LENGTH) + 256(PAYLOAD) 
                    //        = 290
                    uint8_t buff[290] = {0};
                    ssize_t len;
                reread:
                    len = read(cursor->socket, buff, 290);
                    if(len == -1){
                        int err = errno;
                        switch(err){
                        case EINTR:
                            goto reread;
                            break;
                        case EAGAIN:
                            // pass
                            break;
                        default:
                            perror("read error");
                            exit(EXIT_FAILURE);
                        }
                    }
                    else if(len == 0){    /* closed */
                        cursor->is_closed = true;
                        close(cursor->socket);
                    }
                    else{
                        uint8_t* device_token;
                        uint16_t payload_len;
                        uint8_t* payload;
                        uint8_t* p = buff;
                        device_token = p;
                        p += sizeof(uint8_t) * 32;
                        payload_len = *((uint16_t*) p);
                        p += sizeof(uint16_t);
                        payload = p;
                        apns_client_write(apns_ctx, device_token, payload, ntohs(payload_len));
                    }
                }
                cursor = cursor->next;
            }
            if(FD_ISSET(tcp_ctx->listen_socket, &readfds)){
                accept_socket(tcp_ctx);
            }

            tcp_ctx->client_sockets = socketlist_delete_closed_socket(tcp_ctx->client_sockets);
        }
    }

    return 0;
}
