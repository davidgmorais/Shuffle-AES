#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

#include "saes.c"

int KEY_LEN = 16;

int main(int argc, char const *argv[])
{
    char salt = 0;
    uint8_t key[KEY_LEN];
    uint8_t sk[KEY_LEN];

    PKCS5_PBKDF2_HMAC_SHA1( argv[1] , -1 , &salt , 1 , 1000 , sizeof(key) , key );
    if (argv[2]) {
        PKCS5_PBKDF2_HMAC_SHA1( argv[2] , -1 , &salt , 1 , 1000 , sizeof(sk) , sk );
    }


    int allocatedSize = 1000;
    char *buffer = malloc(allocatedSize * sizeof(char));
    strcpy(buffer, "");

    char * line = NULL;
    size_t len = 0;
    ssize_t lineSize = 0;

    while ((lineSize = getline(&line, &len, stdin)) != EOF) 
    {
        if (line[0] == '\n') {
            break;
        }

        int newSize = strlen(buffer) + lineSize +1;
        if (newSize > allocatedSize) {
            allocatedSize = newSize + 1000;
            buffer = realloc(buffer, allocatedSize * sizeof(char));
        }
        strcat(buffer, line);

        free(line);
        line = NULL;
    } 
    if (line) free(line);

    uint8_t *in = &buffer[0];
    int pads = pkcs7_padder(in, strlen(buffer), allocatedSize);

    lineSize = strlen(in);
    uint8_t out[lineSize];
    
    struct SAES_ctx ctx;
    SAES_init_ctx(&ctx, key, argv[2] ? sk : NULL);
    
    SAES_ecb_encrypt(in, out, lineSize, &ctx);
    for (int i=0; i<lineSize; i++) printf("%c", out[i]);

    free(buffer);
    return 0;
}
