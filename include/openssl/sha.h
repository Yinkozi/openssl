/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
# define HEADER_SHA_H

# include <openssl/e_os2.h>
# include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define SHA_LONG unsigned int

# define SHA_LBLOCK      16
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
# define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

int YSHA1_Init(SHA_CTX *c);
int YSHA1_Update(SHA_CTX *c, const void *data, size_t len);
int YSHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *YSHA1(const unsigned char *d, size_t n, unsigned char *md);
void YSHA1_Transform(SHA_CTX *c, const unsigned char *data);

# define YSHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct YSHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} YSHA256_CTX;

int SHA224_Init(YSHA256_CTX *c);
int SHA224_Update(YSHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, YSHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
int YSHA256_Init(YSHA256_CTX *c);
int YSHA256_Update(YSHA256_CTX *c, const void *data, size_t len);
int YSHA256_Final(unsigned char *md, YSHA256_CTX *c);
unsigned char *YSHA256(const unsigned char *d, size_t n, unsigned char *md);
void YSHA256_Transform(YSHA256_CTX *c, const unsigned char *data);

# define SHA224_DIGEST_LENGTH    28
# define YSHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define YSHA512_DIGEST_LENGTH    64

/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
# define YSHA512_CBLOCK   (SHA_LBLOCK*8)
# if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#  define SHA_LONG64 unsigned __int64
#  define U64(C)     C##UI64
# elif defined(__arch64__)
#  define SHA_LONG64 unsigned long
#  define U64(C)     C##UL
# else
#  define SHA_LONG64 unsigned long long
#  define U64(C)     C##ULL
# endif

typedef struct YSHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[YSHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} YSHA512_CTX;

int SHA384_Init(YSHA512_CTX *c);
int SHA384_Update(YSHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, YSHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
int YSHA512_Init(YSHA512_CTX *c);
int YSHA512_Update(YSHA512_CTX *c, const void *data, size_t len);
int YSHA512_Final(unsigned char *md, YSHA512_CTX *c);
unsigned char *YSHA512(const unsigned char *d, size_t n, unsigned char *md);
void YSHA512_Transform(YSHA512_CTX *c, const unsigned char *data);

#ifdef  __cplusplus
}
#endif

#endif
