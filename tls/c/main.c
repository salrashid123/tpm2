/*
# export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
# 
# cat /etc/ssl/openssl.cnf
# [openssl_init]
# providers = provider_sect
# ssl_conf = ssl_sect

# [provider_sect]
# default = default_sect
# tpm2 = tpm2_sect

# [tpm2_sect]
# activate = 1
#
# [default_sect]
# activate = 1


$ openssl list --providers
    Providers:
    default
        name: OpenSSL Default Provider
        version: 3.0.2
        status: active
    tpm2
        name: TPM 2.0 Provider
        version: 1.3.0
        status: active

$ openssl req  --provider tpm2 --provider default -x509 -newkey rsa \
   -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 \
   -keyout key.pem -out cert.pem -sha256 -days 365

$ openssl rsa -provider tpm2  -provider default -in key.pem --text

gcc main.c -lcrypto -lssl -o server


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>


int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{



    OSSL_PROVIDER* provider;

    provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        printf("Failed to load Default provider\n");
        exit(EXIT_FAILURE);
    }
    printf("Default Provider name: %s\n", OSSL_PROVIDER_get0_name(provider));

    OSSL_PROVIDER* custom_provider = OSSL_PROVIDER_load(NULL, "tpm2");
    if (custom_provider == NULL) {
      perror("Could not create custom provider");
      exit(EXIT_FAILURE);
    }
    printf("Custom Provider name: %s\n", OSSL_PROVIDER_get0_name(custom_provider));



    int sock;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}
*/