#include <stdint.h>

#ifndef CUPBKDF2_CUDA
#define CUPBKDF2_CUDA

#define THREADS_PER_BLOCK 64

#define GET_BE(n,b,i)                            \
{                                                \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )      \
        | ( (uint32_t) (b)[(i) + 1] << 16 )      \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )      \
        | ( (uint32_t) (b)[(i) + 3]       );     \
}

#define PUT_BE(n,b,i)                             \
{                                                 \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 ); \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 ); \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 ); \
    (b)[(i) + 3] = (unsigned char) ( (n)       ); \
}

#define GET_BE64(n,b,i)                          \
{                                                \
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )      \
        | ( (uint64_t) (b)[(i) + 1] << 48 )      \
        | ( (uint64_t) (b)[(i) + 2] << 40 )      \
        | ( (uint64_t) (b)[(i) + 3] << 32 )      \
        | ( (uint64_t) (b)[(i) + 4] << 24 )      \
        | ( (uint64_t) (b)[(i) + 5] << 16 )      \
        | ( (uint64_t) (b)[(i) + 6] << 8  )      \
        | ( (uint64_t) (b)[(i) + 7]       );     \
}

#define PUT_BE64(n,b,i)                           \
{                                                 \
    (b)[(i)    ] = (unsigned char) ( (n) >> 56 ); \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 48 ); \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 40 ); \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 32 ); \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 24 ); \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 16 ); \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 8  ); \
    (b)[(i) + 7] = (unsigned char) ( (n)       ); \
}


typedef struct {
    uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;

typedef struct {
    uint32_t h0,h1,h2,h3,h4,h5,h6,h7;
} SHA256_DEV_CTX;

typedef struct {
    uint64_t h0,h1,h2,h3,h4,h5,h6,h7;
} SHA512_DEV_CTX;


#define CPY_DEVCTX(src, dst) \
{ \
    dst.h0 = src.h0; dst.h1 = src.h1; \
    dst.h2 = src.h2; dst.h3 = src.h3; \
    dst.h4 = src.h4; \
}

#define CPY_DEVCTX2_openSSL(src, dst) \
{ \
    dst.h0 = src.h[0]; dst.h1 = src.h[1]; \
    dst.h2 = src.h[2]; dst.h3 = src.h[3]; \
    dst.h4 = src.h[4]; dst.h5 = src.h[5]; \
	dst.h6 = src.h[6]; dst.h7 = src.h[7]; \
}

#define CPY_DEVCTX2(src, dst) \
{ \
    dst.h0 = src.h0; dst.h1 = src.h1; \
    dst.h2 = src.h2; dst.h3 = src.h3; \
    dst.h4 = src.h4; dst.h5 = src.h5; \
	dst.h6 = src.h6; dst.h7 = src.h7; \
}


#define CUSAFECALL(cmd) \
{ \
    ret = (cmd); \
    if (ret != CUDA_SUCCESS) \
        goto errout; \
}

#define ALIGN_UP(offset, alignment) \
    (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

typedef struct {
    SHA_DEV_CTX ctx_ipad;
    SHA_DEV_CTX ctx_opad;
    SHA_DEV_CTX e1;
    SHA_DEV_CTX e2;
} gpu_inbuffer;

typedef struct {
    SHA256_DEV_CTX ctx_ipad;
    SHA256_DEV_CTX ctx_opad;
    SHA256_DEV_CTX e1;
} gpu_inbuffer256;

typedef struct {
    SHA512_DEV_CTX ctx_ipad;
    SHA512_DEV_CTX ctx_opad;
    SHA512_DEV_CTX e1;
} gpu_inbuffer512;


typedef struct {
    SHA_DEV_CTX pmk1;
    SHA_DEV_CTX pmk2;
} gpu_outbuffer;

typedef struct {
    SHA256_DEV_CTX pmk;
} gpu_outbuffer256;

typedef struct {
    SHA512_DEV_CTX pmk;
} gpu_outbuffer512;

int cuda_pbkdf2_hmac_sha1_32(const uint8_t **pwdlst, size_t num_pwds, const uint8_t *salt, 
						  size_t salt_len, uint32_t iterations, uint8_t **key){


#endif

