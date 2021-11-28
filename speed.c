#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "saes.c"

void evalute_saes(uint8_t *buffer, size_t size)
{
    uint8_t key[16]; 
    uint8_t sk[16]; 
    uint8_t cipher[size];
    uint8_t plaint[size];
    struct SAES_ctx ctx;
    struct timespec enc_start, enc_stop;
    struct timespec dec_start, dec_stop;
    double enc_time;
    double dec_time;
    double best_enc_time = 15 * 1e9;
    double best_dec_time = 15 * 1e9;

    int measurements = 100000;
    for (int i=0; i < measurements; i++)
    {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(sk, sizeof(sk));
        SAES_init_ctx(&ctx, key, sk);

        clock_gettime( CLOCK_REALTIME, &enc_start);
        SAES_ecb_encrypt(buffer, cipher, size, &ctx);
        clock_gettime( CLOCK_REALTIME, &enc_stop);

        enc_time = ((enc_stop.tv_sec - enc_start.tv_sec) * 1e9)
                   + (enc_stop.tv_nsec - enc_start.tv_nsec);
        if (enc_time < best_enc_time) {
            best_enc_time = enc_time;
        }


        clock_gettime( CLOCK_REALTIME, &dec_start);
        SAES_ecb_decrypt(cipher, plaint, size, &ctx);
        clock_gettime( CLOCK_REALTIME, &dec_stop);

        dec_time = ((dec_stop.tv_sec - dec_start.tv_sec) * 1e9)
                   + (dec_stop.tv_nsec - dec_start.tv_nsec);
        if (dec_time < best_dec_time) {
            best_dec_time = dec_time;
        }
    }

    printf("%-10s \t %22.3f \t %22.3f\n", "SAES", best_enc_time, best_dec_time);
}

void evalute_aes(uint8_t *buffer, size_t size)
{
    uint8_t key[16]; 
    uint8_t cipher[size];
    uint8_t plaint[size];
    struct SAES_ctx ctx;
    struct timespec enc_start, enc_stop;
    struct timespec dec_start, dec_stop;
    double enc_time;
    double dec_time;
    double best_enc_time = 15 * 1e9;
    double best_dec_time = 15 * 1e9;

    int measurements = 100000;
    for (int i=0; i < measurements; i++)
    {
        RAND_bytes(key, sizeof(key));
        SAES_init_ctx(&ctx, key, NULL);

        clock_gettime( CLOCK_REALTIME, &enc_start);
        SAES_ecb_encrypt(buffer, cipher, size, &ctx);
        clock_gettime( CLOCK_REALTIME, &enc_stop);

        enc_time = ((enc_stop.tv_sec - enc_start.tv_sec) * 1e9)
                   + (enc_stop.tv_nsec - enc_start.tv_nsec);
        if (enc_time < best_enc_time) {
            best_enc_time = enc_time;
        }


        clock_gettime( CLOCK_REALTIME, &dec_start);
        SAES_ecb_decrypt(cipher, plaint, size, &ctx);
        clock_gettime( CLOCK_REALTIME, &dec_stop);

        dec_time = ((dec_stop.tv_sec - dec_start.tv_sec) * 1e9)
                   + (dec_stop.tv_nsec - dec_start.tv_nsec);
        if (dec_time < best_dec_time) {
            best_dec_time = dec_time;
        }
    }

    printf("%-10s \t %22.3f \t %22.3f\n", "AES", best_enc_time, best_dec_time);
}

void evalute_openssl_aes(uint8_t *buffer, size_t size)
{
    uint8_t key[16]; 
    uint8_t sk[16]; 
    uint8_t cipher[size];
    uint8_t plaint[size];
    EVP_CIPHER_CTX *ctx;
    struct timespec enc_start, enc_stop;
    struct timespec dec_start, dec_stop;
    double enc_time;
    double dec_time;
    double best_enc_time = 15 * 1e9;
    double best_dec_time = 15 * 1e9;
    int outLen = 0;

    int measurements = 100000;
    for (int i=0; i < measurements; i++)
    {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(sk, sizeof(sk));
        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit(ctx, EVP_aes_128_ecb(), key, NULL, 1);

        clock_gettime(CLOCK_REALTIME, &enc_start);
        EVP_CipherUpdate(ctx, cipher, &outLen, buffer, size);
        clock_gettime(CLOCK_REALTIME, &enc_stop);
        EVP_CIPHER_CTX_free(ctx);

        enc_time = ((enc_stop.tv_sec - enc_start.tv_sec) * 1e9)
                   + (enc_stop.tv_nsec - enc_start.tv_nsec);
        if (enc_time < best_enc_time) {
            best_enc_time = enc_time;
        }

        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit(ctx, EVP_aes_128_ecb(), key, NULL, 0);

        clock_gettime( CLOCK_REALTIME, &dec_start);
        EVP_DecryptUpdate(ctx, plaint, &outLen, cipher, size);
        clock_gettime( CLOCK_REALTIME, &dec_stop);

        dec_time = ((dec_stop.tv_sec - dec_start.tv_sec) * 1e9)
                   + (dec_stop.tv_nsec - dec_start.tv_nsec);
        if (dec_time < best_dec_time) {
            best_dec_time = dec_time;
        }
        EVP_CIPHER_CTX_free(ctx);
    }

    printf("%-10s \t %22.3f \t %22.3f\n", "OpenSSL AES", best_enc_time, best_dec_time);
}

int main(int argc, char const *argv[])
{
    size_t size = 4*1024;
    uint8_t *buffer = malloc(size * sizeof(uint8_t));

    FILE *fp;
    fp = fopen("/dev/urandom","r");
    fread(buffer, sizeof(uint8_t), size, fp);
    fclose(fp);

    printf("%-10s \t %22s \t %22s\n", "Algoritm", "Encryption time (ns)", "Decryption time (ns)");
    evalute_saes(buffer, size);
    evalute_aes(buffer, size);
    evalute_openssl_aes(buffer, size);

    free(buffer);
    return 0;
}
