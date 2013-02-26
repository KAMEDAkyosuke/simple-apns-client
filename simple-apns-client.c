#include "simple-apns-client.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include <openssl/err.h>

#ifdef __APPLE__

#define SSL_CTX_free(ctx) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_CTX_free((ctx)) \
    _Pragma("clang diagnostic pop")

#define SSL_shutdown(ctx) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_shutdown((ctx)) \
    _Pragma("clang diagnostic pop")

#define SSL_free(ctx) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_shutdown((ctx)) \
    _Pragma("clang diagnostic pop")

#define SSL_load_error_strings() \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_load_error_strings() \
    _Pragma("clang diagnostic pop")

#define SSL_load_error_strings() \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_load_error_strings() \
    _Pragma("clang diagnostic pop")

#define SSL_library_init() \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_library_init() \
    _Pragma("clang diagnostic pop")

#define SSL_CTX_new(method) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_CTX_new((method))                                             \
    _Pragma("clang diagnostic pop")

#define SSL_CTX_use_certificate_chain_file(ctx, path) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_CTX_use_certificate_chain_file((ctx), (path))                \
    _Pragma("clang diagnostic pop")

#define SSL_CTX_use_PrivateKey_file(ctx, path, filetype) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_CTX_use_PrivateKey_file((ctx), (path), (filetype))     \
    _Pragma("clang diagnostic pop")

#define SSL_new(ctx)                    \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_new((ctx))                                             \
    _Pragma("clang diagnostic pop")

#define SSL_set_fd(ctx, fd)             \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_set_fd((ctx), (fd))                                           \
    _Pragma("clang diagnostic pop")

#define SSL_connect(ssl)             \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_connect((ssl))                                                \
    _Pragma("clang diagnostic pop")

#define ERR_print_errors_fp(fd)             \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    ERR_print_errors_fp((fd))                                                \
    _Pragma("clang diagnostic pop")

#define SSL_get_error(ssl, r)        \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_get_error((ssl), (r))                                         \
    _Pragma("clang diagnostic pop")

#define SSL_write(ssl, buf, len)        \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"") \
    SSL_write((ssl), (buf), (len))                                    \
    _Pragma("clang diagnostic pop")

#endif

static void get_tcp_socket(apns_client_ctx_t* ctx);

apns_client_ctx_t* apns_client_new()
{
    apns_client_ctx_t* ctx = (apns_client_ctx_t*) calloc(1, sizeof(apns_client_ctx_t));
    ctx->host_name = NULL;
    ctx->port = 0;
    ctx->socket = 0;;

    ctx->certificate_chain_file_path = NULL;
    ctx->private_key_file_path = NULL;

    ctx->ssl_ctx = NULL;
    ctx->ssl = NULL;
    return ctx;
}

void apns_client_free(const apns_client_ctx_t *ctx)
{
    if(ctx->ssl != NULL){
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
    if(ctx->ssl_ctx != NULL){
        SSL_CTX_free(ctx->ssl_ctx);
    }
    if(ctx->socket != 0){
        close(ctx->socket);
    }
    free((void*) ctx);
}

void apns_client_connect(apns_client_ctx_t* ctx)
{
    get_tcp_socket(ctx);

    struct hostent *host;
    struct sockaddr_in addr;
    host = gethostbyname(ctx->host_name);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

 reconnect:
    if((connect(ctx->socket, (struct sockaddr *) &addr, sizeof(addr))) < 0){
        int err = errno;
        switch(err){
        case EISCONN:
            puts("connected");
            break;
        case EALREADY:
        case EINTR:
        case EINPROGRESS:
            puts("wait");
            {
                /* sleep */
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                if(select(0, NULL, NULL, NULL, &tv) == -1){
                    perror("select error");
                    exit(EXIT_FAILURE);
                }
                puts("re connect");
                goto reconnect;
                break;
            }
        default:
            {
                perror("connect error");
                exit(EXIT_FAILURE);
            }
        }
    }

    // SSL
    /* TODO : check error */
    SSL_load_error_strings();
    SSL_library_init();
    ctx->ssl_ctx = SSL_CTX_new(SSLv3_client_method());
    if(ctx->ssl_ctx == NULL){
        fprintf(stderr, "ERROR : SSL_CTX_new\n");
        exit(EXIT_FAILURE);
    }
    if((SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, ctx->certificate_chain_file_path)) != 1){
        fprintf(stderr, "ERROR : SSL_CTX_use_certificate_chain_file\n");
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->private_key_file_path, SSL_FILETYPE_PEM) != 1){
        fprintf(stderr, "ERROR : SSL_CTX_use_PrivateKey_file\n");
        exit(EXIT_FAILURE);
    }
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if(ctx->ssl == NULL){
        fprintf(stderr, "ERROR : SSL_new\n");
        exit(EXIT_FAILURE);
    }
    
    if(SSL_set_fd(ctx->ssl, ctx->socket) != 1){
        fprintf(stderr, "ERROR : SSL_set_fd\n");
        exit(EXIT_FAILURE);
    }

    int r;
 re_ssl_connect:
    if((r = SSL_connect(ctx->ssl)) < 0 ){
        ERR_print_errors_fp(stderr);
        r = SSL_get_error(ctx->ssl, r);
        fprintf(stderr, "SSL_connect error : SSL_get_error = %d\n", r);
        switch(r){
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            {
                /* sleep */
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                if(select(0, NULL, NULL, NULL, &tv) == -1){
                    perror("select error");
                    exit(EXIT_FAILURE);
                }
                puts("re ssl connect");
                goto re_ssl_connect;
            }
            break;
        default:
            fprintf(stderr, "ERROR : SSL_connect\n");
            exit(EXIT_FAILURE);
        }
    }
}

int apns_client_write(const apns_client_ctx_t* ctx, const uint8_t* device_token, const uint8_t* payload, uint16_t payload_len)
{
    uint8_t command = 0;
    uint16_t token_length = htons(32);
    uint16_t payload_length = htons(payload_len);

    /* buffer size = 1(COMMAND) + 2(TOKEN_LENGTH) + 32(TOKEN) + 2(PAYLOAD LENGTH) + 256(PAYLOAD)
     *             = 293
     */
                    
    char buff[293] = {0};
    char* p = buff;
    
    // COMMAND
    *p = command;
    p++;
    // TOKEN LENGTH
    memcpy(p, &token_length, sizeof(uint16_t));
    p += sizeof(uint16_t);
    // TOKEN
    memcpy(p, device_token, 32);
    p+=32;
    // PAYLOAD LENGTH    
    memcpy(p, &payload_length, sizeof(uint16_t));
    p += sizeof(uint16_t);
    memcpy(p, payload, payload_len);
    p += payload_len;

    int len;

    len = SSL_write(ctx->ssl, &buff, p - buff);
    if(len < 0){
        // TODO:
    }
    else if(len == 0){
        // TODO:
    }
    else{
        // TODO:
    }
    return len;
}

static void get_tcp_socket(apns_client_ctx_t* ctx)
{
    if((ctx->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    int flags;
    flags = fcntl(ctx->socket, F_GETFL, 0);
    if (flags < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }
    if (fcntl(ctx->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }
}

