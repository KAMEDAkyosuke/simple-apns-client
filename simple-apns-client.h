#ifndef SIMPLE_APNS_CLIENT_H
#define SIMPLE_APNS_CLIENT_H

#include <stdint.h>

#include <openssl/ssl.h>

typedef enum {
    APNS_CLIENT_RETURN_OK = 0,
    APNS_CLIENT_RETURN_ERROR,
} APNS_CLIENT_RETURN;

typedef struct {
    char* host_name;    /* "gateway.sandbox.push.apple.com"
                         * "gateway.push.apple.com"
                         */
    int port;
    int socket;
    
    // 証明書
    char* certificate_chain_file_path;
    char* private_key_file_path;
    
    // SSL
	SSL_CTX *ssl_ctx;
	SSL *ssl;
    
    // ERROR
    char* error_message;
} apns_client_ctx_t;

apns_client_ctx_t* apns_client_new();
void apns_client_free(const apns_client_ctx_t *ctx);

APNS_CLIENT_RETURN apns_client_connect(apns_client_ctx_t* ctx);

int apns_client_write(const apns_client_ctx_t* ctx, const uint8_t* device_token, const uint8_t* payload, uint16_t payload_len);

#endif
