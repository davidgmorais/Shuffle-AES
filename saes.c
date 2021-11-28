#include <stdint.h>
#include <wmmintrin.h>
#include "saes.h"
#include <string.h>



static int shift_offset[4] = {0, 1, 2, 3};
static uint8_t inv_sbox[256];



// PRIVATE FUNCTIONS
/*
* Private function used mainly for debug, where it prints the current state of the message
* in a matrix form, characteristic of the AES cipher.
*/
static void print_state(uint8_t* state)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x\t", state[(4*j) + i]);
        }   
        printf("\n");
    }
    printf("\n\n");
}

// https://crypto.stackexchange.com/questions/82095/constant-time-multiplication-in-gf28

static inline uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    for (int i = 7; i >= 0; i--) {
       res = (-(b >> i & 1) & a) ^(-(res >> 7) & 0x1b) ^ (res + res);
    }
}

/*
* Private function used to assist in the generation of each round key by using 
* _mm_shuffle_epi32(a, imm8) that shuffle 32-bit integers in a using the control, 
* _mm_slli_si128(a, imm8) that shift a left by imm8 bytes while shifting in zeros, and
* _mm_xor_si128(a, b) which is the bitwise XOR of a and b.
* returns the round key
*/
static __m128i AES_128_ASSIST(__m128i tmp1, __m128i tmp2)
{
    __m128i temp3;
    tmp2 = _mm_shuffle_epi32 (tmp2 ,0xff);
    temp3 = _mm_slli_si128 (tmp1, 0x4);
    tmp1 = _mm_xor_si128 (tmp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    tmp1 = _mm_xor_si128 (tmp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    tmp1 = _mm_xor_si128 (tmp1, temp3);
    tmp1 = _mm_xor_si128 (tmp1, tmp2);
    return tmp1;
} 

/*
* Private function to perform key explansion, returning the 11 round keys to be used in AES cipher, where
* the first round key is the key itself.
* source: https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
*/
static void KeyExpansion(uint8_t* roundKey, const uint8_t* key)
{
    __m128i tmp1, tmp2;
    __m128i *rkeys = (__m128i*)roundKey;

    // First round key is the actual key
    tmp1 = _mm_loadu_si128((__m128i*)key);
    rkeys[0] = tmp1; 
    // Generate the remaider of the round keys by using the instruction AESKEYGENASSIST xmm1, xmm2/m128u, imm8 (using an 8-bit
    // constant (imm8) with a 128-bit key specified in xmm2/m128 and stores the result in xmm1)  which is later combined with the
    // key, throught the function AES_128_ASSIST
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x1);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[1] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x2);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[2] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x4);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[3] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x8);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[4] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x10);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[5] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x20);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[6] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x40);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[7] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x80);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[8] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x1b);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[9] = tmp1;
    tmp2 = _mm_aeskeygenassist_si128 (tmp1,0x36);
    tmp1 = AES_128_ASSIST(tmp1, tmp2);
    rkeys[10] = tmp1; 
}

/*
* Private function used to shuffle an sboc passed as the first param, using part of the shuffle key
* passed as the second param. 
* This is done by iterating through the S-Box and swapping values from the index to another index
* generated based on the SK itself.
*/
static void shuffleSBox(uint8_t* shuffledBox, const uint8_t* sk)
{
    size_t n = 256;
    size_t i;

    for (int i = 0; i < 256; i++)
    {
        int j = (int) (sk[i % 8] ^ i);
        uint8_t tmp = shuffledBox[i];
        shuffledBox[i] = shuffledBox[j];
        shuffledBox[j] = tmp;
    }
}

/*
* Private function used to invert an sbox passed as the second param to the
* array passed in the first param. 
* The value v in the position p becomes the position of the inverted s-box
* in which the value p can be found.  
*/
static void invertSBox(uint8_t* invSbox, const uint8_t* sbox)
{
    uint8_t formedXored;
    for (int p = 0; p < 256; p++)
    {
        formedXored = sbox[p];
        invSbox[formedXored] = (uint8_t) p;
    }

}

/*
* Private function to perform the addRoundKey of the AES, by iterating thorough the message
* adn doing the binary XOR with the rounkey's byte in the same position. 
*/
static void addRoundKey(uint8_t* message, const uint8_t* roundKey)
{
    for (int i = 0; i < 16; i++)
    {
        message[i] ^= roundKey[i];
    }
}

/*
* Private function used to perform the subBytes step of the AES, where a byte s in the message is
* substituted with the value in index s of the s-box passed as a param.
*/
static void subBytes(uint8_t* message, const uint8_t* sbox)
{
    for (int i=0; i<16; i++)
    {
        message[i] = sbox[(message[i])];
    }
}

/*
* Private function to perform the inversion of the AES subBytes step by, similarly to subBytes, substitute
* a value v by the value in the inverse s-box passed as a param in the position v.
*/
static void invSubBytes(uint8_t* message, const uint8_t* inv_sbox)
{
    for (int i=0; i<16; i++)
    {
        message[i] = inv_sbox[(message[i])];
    }
}

/*
* Private function to perform a shifRows in the message, by shifting the bytes in a given row r by subtrating
* the offset given by shiftOffsets[r] to the index, where shiftOffsets is passed as the second param.
*/
static void shiftRows(uint8_t* message, int shiftOffsets[4])
{

    for (int c=0; c<4; c++)
    {
        uint8_t row[4];
        for (int r=0; r<4; r++)
        {
            row[r] = message[(4*r) + c];
        }

        uint8_t shifted_row[4];
        for (int index=0; index<4; index++)
        {
            // offset of row given by shiftOffsets[c]
            int shifted_index = (4 + index - shiftOffsets[c]) % 4;
            shifted_row[shifted_index] = row[index];
        }

        for (int r=0; r<4; r++)
        {
            message[(4*r) + c] = shifted_row[r];
        }
    }

}

/*
* Private function to perform the inverse operation of shifRows in the message, by shifting the bytes in a 
* given row r by adding the offset given by shiftOffsets[r] to the index, where shiftOffsets is passed as 
* the second param.
*/
static void invShiftRows(uint8_t* message, int shiftOffsets[4])
{
    for (int c=0; c<4; c++)
    {
        uint8_t row[4];
        for (int r=0; r<4; r++)
        {
            row[r] = message[(4*r) + c];
        }

        uint8_t shifted_row[4];
        for (int index=0; index<4; index++)
        {
            // offset given by shiftOffsets[c]
            int shifted_index = (index + shiftOffsets[c]) % 4;
            shifted_row[shifted_index] = row[index];
        }

        for (int r=0; r<4; r++)
        {
            message[(4*r) + c] = shifted_row[r];
        }
    }
}

/*
* Private function to permorme a mixColumns operation, by doing a matrix multiplication in GF(2^() of every
* columns in the message by the matrix passed as the second param. This method can also be used to invert
* itself, but passing the inverse matrix instead as the seconf param.
*/
static void mixColumns(uint8_t* message, const uint8_t matrix[4][4])
{
    for (int c=0; c<4; c++)
    {
        uint8_t a[4];
        for (int r=0; r<4; r++)
        {
            a[r] = message[(4*c) + r];
        }

        for (int i=0; i<4; i++)
        {
            message[4*c + i] = gmul(a[0], matrix[i][0]) ^ gmul(a[1], matrix[i][1]) ^ gmul(a[2], matrix[i][2]) ^ gmul(a[3], matrix[i][3]);
        }        
    }
}

/*
* Private function to perform encryption on the shuffle round.
*/
static void aes_enc_shuffle_round(uint8_t* message, int round, struct SAES_ctx *ctx)
{
    subBytes(message, ctx->sbox);
    shiftRows(message, ctx->shiftOffset);
    mixColumns(message, ctx->mixColumnMatrix);
}

/*
* Private function to perform the decryption on the previous round to the shuffled one.
*/
static void aes_dec_shuffle_round_prev(uint8_t* message, int round, struct SAES_ctx *ctx)
{   
    invShiftRows(message, ctx->shiftOffset);
    invSubBytes(message, ctx->inv_sbox);
}

/*
* Private function to perform the decryption on the shuffled round.
*/
static void aes_dec_shuffle_round(uint8_t* message, int round, struct SAES_ctx *ctx)
{   
    invShiftRows(message, shift_offset);
    invSubBytes(message, inv_sbox);
    
    mixColumns(message, ctx->invMixColumnMatrix);
}



// PUBLIC FUNCTIONS
/*
* Function to initialie the context of the SAES, by doing the key expanition and, if sk is 
* passed as a param, to create the key, offsets, s-boxs and matrixes to be used in the 
* special round. If no SK is passed, the its assumed that a normal AES should be performed.
*/
void SAES_init_ctx(struct SAES_ctx *ctx, const uint8_t* key, const uint8_t* sk)
{
    KeyExpansion(ctx->roundKey, key);

    if (!sk) {
        ctx->inShuffleMode = 0;
        return;
    }
    ctx->inShuffleMode = 1;

    // choice of shuffle round (1 to 9) based on the 2 first bytes of the SK
    ctx->shuffleRoundNr = 1 + (((int) sk[0] | (sk[1] << 8)) % 9);

    // choice of the offset used to rotate the round key in the shuffle round, based on the
    // 3th and 4th bytes of the SK
    int offset = (int)(sk[2] | (sk[3] << 8))%16;
    for (int i = 0; i < 16; i++)
    {
        ctx->rotatedKey[(i+offset)%16] = ctx->roundKey[16*ctx->shuffleRoundNr + i];
        ctx->invRotatedKey[(i+offset)%16] = ctx->roundKey[16*ctx->shuffleRoundNr + i];
    }
    
    // uses the next 8 bytes of the SK to shuffle the original S-Box, inverting it afterwards
    uint8_t skSlice[8] = {sk[4], sk[5], sk[6], sk[7], sk[8], sk[9], sk[10], sk[11]};
    memcpy(ctx->sbox, &sbox[0], 256*sizeof(sbox[0]));
    shuffleSBox(ctx->sbox, skSlice);
    invertSBox(ctx->inv_sbox, ctx->sbox);
    invertSBox(inv_sbox, sbox);

    // choice of the permutation of offsets to be applied in the shiftRow phase, based on the
    // 13th and 14th bytes of the SK.
    int shifRowByteShift[4] = {0, 1, 2, 3};
    uint16_t seed = sk[12] | (sk[13] << 8);
    srand((unsigned int) seed);
    for (int i = 0; i < 4; i++) 
    {
        int index = rand() % 4;
        int temp = shifRowByteShift[i];
        shifRowByteShift[i] = shifRowByteShift[index];
        shifRowByteShift[index] = temp;
    }
    for (int i=0; i <4; i++) ctx->shiftOffset[i] = shifRowByteShift[i];

    // choice of the offset to apply to the matrix used in the mixColumns phase of the special
    // round, based on the 15th and 16th (last two) bytes of the SK.
    offset = (int) (sk[14] | (sk[15] << 8)) % 4;
    for (int i=0; i<4; i++)
    {
        for (int j=0; j<4; j++)
        {
            ctx->mixColumnMatrix[i][j] = mixColumnsMatrix[i][(j + offset)%4]; 
            ctx->invMixColumnMatrix[i][j] = invMixColumnsMatrix[i][(j + offset)%4]; 
        }
    }

    // prepare the round key of the special round to the decryption process, by applying to it the
    // invMixMatrix process, using the inverse matrix used in the special round.
    mixColumns(ctx->invRotatedKey, ctx->invMixColumnMatrix);

}

/*
* Function to perform the encryption in ECB mode of in to the buffer out, with size size. This
* function assumes that the input is multiple of 16 and is based on a function of the Inter 
* White Paper for AES assembly instuctions.
*/
void SAES_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t size, struct SAES_ctx *ctx)
{
    __m128i m;
    uint8_t tmp[16];
    if (size % 16)
    {
        size = size/16 + 1;
    } else {
        size /= 16;
    }

    #pragma omp parallel for 
    for (int i = 0; i < size; i++)
    {
        m = _mm_loadu_si128(&((__m128i*)in)[i]);
        m = _mm_xor_si128(m, ((__m128i*)(ctx->roundKey))[0]);

        for (int round=1; round < 10; round++)
        {
            if (ctx->inShuffleMode && ctx->shuffleRoundNr == round) 
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], m);
                aes_enc_shuffle_round(tmp, round, ctx);
                m = _mm_loadu_si128((__m128i*)tmp);

                // add round key
                m = _mm_xor_si128(m, ((__m128i*)(ctx->rotatedKey))[0]);

            } else 
            {
                m = _mm_aesenc_si128(m, ((__m128i*)(ctx->roundKey))[round]);
            }
        }

        m = _mm_aesenclast_si128(m, ((__m128i*)(ctx->roundKey))[10]);
        _mm_storeu_si128 (&((__m128i*)out)[i], m);
    }

}

/*
* Function to perform the decryption in ECB mode of in to the buffer out, with size size. This
* function assumes that the input is multiple of 16 and is based on a function of the Inter 
* White Paper for AES assembly instuctions.
*/
void SAES_ecb_decrypt(const uint8_t *in, uint8_t *out, size_t size, struct SAES_ctx *ctx)
{
    __m128i m;
    uint8_t tmp[16];
    if (size % 16)
    {
        size = size/16 + 1;
    } else {
        size /= 16;
    }

    for (int i = 0; i < size; i++)
    {
        m = _mm_loadu_si128(&((__m128i*)in)[i]);
        m = _mm_xor_si128(m, ((__m128i*)(ctx->roundKey))[10]);

        for (int round=9; round > 0; round--)
        {
            if (ctx->inShuffleMode && ctx->shuffleRoundNr - 1 == round) 
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], m);
                aes_dec_shuffle_round_prev(tmp, round, ctx);
                m = _mm_loadu_si128((__m128i*)tmp);

                // inv mix columns
                m = _mm_aesimc_si128(m);
                
                // add round key
                m = _mm_xor_si128(m,  _mm_aesimc_si128(((__m128i*)(ctx->roundKey))[round]));

            } else if (ctx->inShuffleMode && ctx->shuffleRoundNr == round)
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], m);
                aes_dec_shuffle_round(tmp, round, ctx);
                m = _mm_loadu_si128((__m128i*)tmp);

                // add round key
                m = _mm_xor_si128(m, ((__m128i*)(ctx->invRotatedKey))[0]);


            } else
            {
                m = _mm_aesdec_si128(m, _mm_aesimc_si128(((__m128i*)(ctx->roundKey))[round]));
            }
        }

        m =_mm_aesdeclast_si128(m, ((__m128i*)(ctx->roundKey))[0]);
        _mm_storeu_si128 (&((__m128i*)out)[i], m);
    }
}

/*
* Function to perform the encryption in CBC mode of in to the buffer out, with size size. This
* function assumes that the input is multiple of 16 and is based on a function of the Inter 
* White Paper for AES assembly instuctions. The encryption of the blocks is done in parallel, 
* once that the encryption process is equal to all of them.
*/
void SAES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t size, uint8_t* iv, struct SAES_ctx *ctx)
{
    __m128i m, feedback;
    uint8_t tmp[16];
    if (size % 16)
    {
        size = size/16 + 1;
    } else {
        size /= 16;
    }

    feedback=_mm_loadu_si128 ((__m128i*)iv); 
    for (int i = 0; i < size; i++)
    {
        m = _mm_loadu_si128(&((__m128i*)in)[i]);
        feedback = _mm_xor_si128 (m, feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)ctx->roundKey)[0]);

        for (int round=1; round < 10; round++)
        {
            if (ctx->inShuffleMode && ctx->shuffleRoundNr == round) 
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], feedback);
                aes_enc_shuffle_round(tmp, round, ctx);
                feedback = _mm_loadu_si128((__m128i*)tmp);

                // add round key
                feedback = _mm_xor_si128(feedback, ((__m128i*)(ctx->rotatedKey))[0]);

            } else 
            {
                feedback = _mm_aesenc_si128(feedback, ((__m128i*)ctx->roundKey)[round]);

            }
        }
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)(ctx->roundKey))[10]);
        _mm_storeu_si128 (&((__m128i*)out)[i], feedback);
    }

}

/*
* Function to perform the decryption in CBC mode of in to the buffer out, with size size. This
* function assumes that the input is multiple of 16 and is based on a function of the Inter 
* White Paper for AES assembly instuctions. The decryption of the blocks is done in parallel, 
* once that the decryption process is equal to all of them.
*/
void SAES_cbc_decrypt(const uint8_t *in, uint8_t *out, size_t size, uint8_t* iv, struct SAES_ctx *ctx)
{
    __m128i m, feedback, last_in;
    uint8_t tmp[16];
    if (size % 16)
    {
        size = size/16 + 1;
    } else {
        size /= 16;
    }

    feedback = _mm_loadu_si128((__m128i*)iv);
    #pragma omp parallel for 
    for (int i = 0; i < size; i++)
    {
        last_in = _mm_loadu_si128(&((__m128i*)in)[i]);
        m = _mm_xor_si128(last_in, ((__m128i*)(ctx->roundKey))[10]);

        for (int round=9; round > 0; round--)
        {
            if (ctx->inShuffleMode && ctx->shuffleRoundNr - 1 == round) 
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], m);
                aes_dec_shuffle_round_prev(tmp, round, ctx);
                m = _mm_loadu_si128((__m128i*)tmp);

                // inv mix columns
                m = _mm_aesimc_si128(m);
                
                // add round key
                m = _mm_xor_si128(m,  _mm_aesimc_si128(((__m128i*)(ctx->roundKey))[round]));

            } else if (ctx->inShuffleMode && ctx->shuffleRoundNr == round)
            {
                _mm_storeu_si128 (&((__m128i*)tmp)[0], m);
                aes_dec_shuffle_round(tmp, round, ctx);
                m = _mm_loadu_si128((__m128i*)tmp);

                // add round key
                m = _mm_xor_si128(m, ((__m128i*)(ctx->invRotatedKey))[0]);


            } else
            {
                m = _mm_aesdec_si128(m, _mm_aesimc_si128(((__m128i*)(ctx->roundKey))[round]));
            }
        }

        m =_mm_aesdeclast_si128(m, ((__m128i*)(ctx->roundKey))[0]);
        m = _mm_xor_si128 (m, feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i], m);
        feedback = last_in;
    }
}

/*
* Function used to pad the contents of buffer if they are not multiple of 16, according to PKCS#7 padding.
* Returns the number of bytes added as padding or, if the buffer is not big enough, -1.
* source: https://github.com/bonybrown/tiny-AES128-C/blob/master/pkcs7_padding.c
*/
int pkcs7_padder(uint8_t *buffer, size_t length, size_t buffer_size)
{
    uint8_t pad = 16 - (length % 16);
    if ((length + pad) > buffer_size) {
        return -1;
    }

    int i=0;
    while (i < pad)
    {
        buffer[length + i] = pad;
        i++;   
    }
    return pad;
}