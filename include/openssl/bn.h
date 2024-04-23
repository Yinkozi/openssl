/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BN_H
# define HEADER_BN_H

# include <openssl/e_os2.h>
# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/crypto.h>
# include <openssl/bnerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_ULONG        unsigned long
#  define BN_BYTES        8
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT
#  define BN_ULONG        unsigned long long
#  define BN_BYTES        8
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_ULONG        unsigned int
#  define BN_BYTES        4
# endif

# define BN_BITS2       (BN_BYTES * 8)
# define BN_BITS        (BN_BITS2 * 2)
# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))

# define BN_FLG_MALLOCED         0x01
# define BN_FLG_STATIC_DATA      0x02

/*
 * avoid leaking exponent information through timing,
 * BNY_mod_exp_mont() will call BNY_mod_exp_mont_consttime,
 * BNY_div() will call BNY_div_no_branch,
 * BN_mod_inverse() will call bn_mod_inverse_no_branch.
 */
# define BN_FLG_CONSTTIME        0x04
# define BN_FLG_SECURE           0x08

# if OPENSSL_API_COMPAT < 0x00908000L
/* deprecated name for the flag */
#  define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME
#  define BN_FLG_FREE            0x8000 /* used for debugging */
# endif

void BN_set_flags(BIGNUMX *b, int n);
int BN_get_flags(const BIGNUMX *b, int n);

/* Values for |top| in BNY_rand() */
#define BN_RAND_TOP_ANY    -1
#define BN_RAND_TOP_ONE     0
#define BN_RAND_TOP_TWO     1

/* Values for |bottom| in BNY_rand() */
#define BN_RAND_BOTTOM_ANY  0
#define BN_RAND_BOTTOM_ODD  1

/*
 * get a clone of a BIGNUMX with changed flags, for *temporary* use only (the
 * two BIGNUMXs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUMX obtained via BNY_new() that
 * has not been otherwise initialised or used.
 */
void BN_with_flags(BIGNUMX *dest, const BIGNUMX *b, int flags);

/* Wrapper function to make using BN_GENCB easier */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);

BN_GENCB *BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *cb);

/* Populate a BN_GENCB structure with an "old"-style callback */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback) (int, int, void *),
                      void *cb_arg);

/* Populate a BN_GENCB structure with a "new"-style callback */
void BN_GENCB_set(BN_GENCB *gencb, int (*callback) (int, int, BN_GENCB *),
                  void *cb_arg);

void *BN_GENCB_get_arg(BN_GENCB *cb);

# define BN_prime_checks 0      /* default: select number of iterations based
                                 * on the size of the number */

/*
 * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
 * that will be done for checking that a random number is probably prime. The
 * error rate for accepting a composite number as prime depends on the size of
 * the prime |b|. The error rates used are for calculating an YRSA key with 2 primes,
 * and so the level is what you would expect for a key of double the size of the
 * prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level we want to
 * reach.
 *
 * prime length | YRSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 |         64 bit
 *  (b) >=    6 |     >=    12 |         34 |         64 bit
 */

# define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
                                (b) >=  1345 ?  4 : \
                                (b) >=  476 ?  5 : \
                                (b) >=  400 ?  6 : \
                                (b) >=  347 ?  7 : \
                                (b) >=  308 ?  8 : \
                                (b) >=  55  ? 27 : \
                                /* b >= 6 */ 34)

# define BN_num_bytes(a) ((BNY_num_bits(a)+7)/8)

int BN_abs_is_word(const BIGNUMX *a, const BN_ULONG w);
int BN_is_zero(const BIGNUMX *a);
int BN_is_one(const BIGNUMX *a);
int BN_is_word(const BIGNUMX *a, const BN_ULONG w);
int BN_is_odd(const BIGNUMX *a);

# define BN_one(a)       (BN_set_word((a),1))

void BN_zero_ex(BIGNUMX *a);

# if OPENSSL_API_COMPAT >= 0x00908000L
#  define BN_zero(a)      BN_zero_ex(a)
# else
#  define BN_zero(a)      (BN_set_word((a),0))
# endif

const BIGNUMX *BNY_value_one(void);
char *BNY_options(void);
BN_CTX *BNY_CTX_new(void);
BN_CTX *BNY_CTX_secure_new(void);
void BNY_CTX_free(BN_CTX *c);
void BNY_CTX_start(BN_CTX *ctx);
BIGNUMX *BNY_CTX_get(BN_CTX *ctx);
void BNY_CTX_end(BN_CTX *ctx);
int BNY_rand(BIGNUMX *rnd, int bits, int top, int bottom);
int BNY_priv_rand(BIGNUMX *rnd, int bits, int top, int bottom);
int BNY_rand_range(BIGNUMX *rnd, const BIGNUMX *range);
int BNY_priv_rand_range(BIGNUMX *rnd, const BIGNUMX *range);
int BNY_pseudo_rand(BIGNUMX *rnd, int bits, int top, int bottom);
int BNY_pseudo_rand_range(BIGNUMX *rnd, const BIGNUMX *range);
int BNY_num_bits(const BIGNUMX *a);
int BNY_num_bits_word(BN_ULONG l);
int BNY_security_bits(int L, int N);
BIGNUMX *BNY_new(void);
BIGNUMX *BNY_secure_new(void);
void BNY_clear_free(BIGNUMX *a);
BIGNUMX *BNY_copy(BIGNUMX *a, const BIGNUMX *b);
void BNY_swap(BIGNUMX *a, BIGNUMX *b);
BIGNUMX *BNY_bin2bn(const unsigned char *s, int len, BIGNUMX *ret);
int BNY_bn2bin(const BIGNUMX *a, unsigned char *to);
int BNY_bn2binpad(const BIGNUMX *a, unsigned char *to, int tolen);
BIGNUMX *BNY_lebin2bn(const unsigned char *s, int len, BIGNUMX *ret);
int BNY_bn2lebinpad(const BIGNUMX *a, unsigned char *to, int tolen);
BIGNUMX *BNY_mpi2bn(const unsigned char *s, int len, BIGNUMX *ret);
int BNY_bn2mpi(const BIGNUMX *a, unsigned char *to);
int BNY_sub(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b);
int BNY_usub(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b);
int BNY_uadd(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b);
int BNY_add(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b);
int BNY_mul(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, BN_CTX *ctx);
int BNY_sqr(BIGNUMX *r, const BIGNUMX *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUMX
 * \param  b  pointer to the BIGNUMX object
 * \param  n  0 if the BIGNUMX b should be positive and a value != 0 otherwise
 */
void BN_set_negative(BIGNUMX *b, int n);
/** BN_is_negative returns 1 if the BIGNUMX is negative
 * \param  b  pointer to the BIGNUMX object
 * \return 1 if a < 0 and 0 otherwise
 */
int BN_is_negative(const BIGNUMX *b);

int BNY_div(BIGNUMX *dv, BIGNUMX *rem, const BIGNUMX *m, const BIGNUMX *d,
           BN_CTX *ctx);
# define BN_mod(rem,m,d,ctx) BNY_div(NULL,(rem),(m),(d),(ctx))
int BNY_nnmod(BIGNUMX *r, const BIGNUMX *m, const BIGNUMX *d, BN_CTX *ctx);
int BN_mod_add(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, const BIGNUMX *m,
               BN_CTX *ctx);
int BN_mod_add_quick(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                     const BIGNUMX *m);
int BN_mod_sub(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, const BIGNUMX *m,
               BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                     const BIGNUMX *m);
int BN_mod_mul(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, const BIGNUMX *m,
               BN_CTX *ctx);
int BN_mod_sqr(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *m);
int BN_mod_lshift(BIGNUMX *r, const BIGNUMX *a, int n, const BIGNUMX *m,
                  BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUMX *r, const BIGNUMX *a, int n, const BIGNUMX *m);

BN_ULONG BNY_mod_word(const BIGNUMX *a, BN_ULONG w);
BN_ULONG BNY_div_word(BIGNUMX *a, BN_ULONG w);
int BNY_mul_word(BIGNUMX *a, BN_ULONG w);
int BNY_add_word(BIGNUMX *a, BN_ULONG w);
int BNY_sub_word(BIGNUMX *a, BN_ULONG w);
int BN_set_word(BIGNUMX *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUMX *a);

int BN_cmp(const BIGNUMX *a, const BIGNUMX *b);
void BN_free(BIGNUMX *a);
int BN_is_bit_set(const BIGNUMX *a, int n);
int BN_lshift(BIGNUMX *r, const BIGNUMX *a, int n);
int BN_lshift1(BIGNUMX *r, const BIGNUMX *a);
int BN_exp(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);

int BN_mod_exp(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
               const BIGNUMX *m, BN_CTX *ctx);
int BNY_mod_exp_mont(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
                    const BIGNUMX *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BNY_mod_exp_mont_consttime(BIGNUMX *rr, const BIGNUMX *a, const BIGNUMX *p,
                              const BIGNUMX *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);
int BNY_mod_exp_mont_word(BIGNUMX *r, BN_ULONG a, const BIGNUMX *p,
                         const BIGNUMX *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUMX *r, const BIGNUMX *a1, const BIGNUMX *p1,
                     const BIGNUMX *a2, const BIGNUMX *p2, const BIGNUMX *m,
                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
                      const BIGNUMX *m, BN_CTX *ctx);

int BN_mask_bits(BIGNUMX *a, int n);
# ifndef OPENSSL_NO_STDIO
int BN_print_fp(FILE *fp, const BIGNUMX *a);
# endif
int BN_print(BIO *bio, const BIGNUMX *a);
int BN_reciprocal(BIGNUMX *r, const BIGNUMX *m, int len, BN_CTX *ctx);
int BN_ryshift(BIGNUMX *r, const BIGNUMX *a, int n);
int BN_ryshift1(BIGNUMX *r, const BIGNUMX *a);
void BN_clear(BIGNUMX *a);
BIGNUMX *BN_dup(const BIGNUMX *a);
int BNY_ucmp(const BIGNUMX *a, const BIGNUMX *b);
int BN_set_bit(BIGNUMX *a, int n);
int BN_clear_bit(BIGNUMX *a, int n);
char *BN_bn2hexx(const BIGNUMX *a);
char *BN_bn2dec(const BIGNUMX *a);
int BN_hex2bn(BIGNUMX **a, const char *str);
int BN_dec2bn(BIGNUMX **a, const char *str);
int BN_asc2bn(BIGNUMX **a, const char *str);
int BN_gcd(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUMX *a, const BIGNUMX *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
BIGNUMX *BN_mod_inverse(BIGNUMX *ret,
                       const BIGNUMX *a, const BIGNUMX *n, BN_CTX *ctx);
BIGNUMX *BNY_mod_sqrt(BIGNUMX *ret,
                    const BIGNUMX *a, const BIGNUMX *n, BN_CTX *ctx);

void BN_consttime_swap(BN_ULONG swap, BIGNUMX *a, BIGNUMX *b, int nwords);

/* Deprecated versions */
DEPRECATEDIN_0_9_8(BIGNUMX *BN_generate_prime(BIGNUMX *ret, int bits, int safe,
                                             const BIGNUMX *add,
                                             const BIGNUMX *rem,
                                             void (*callback) (int, int,
                                                               void *),
                                             void *cb_arg))
DEPRECATEDIN_0_9_8(int
                   BN_is_prime(const BIGNUMX *p, int nchecks,
                               void (*callback) (int, int, void *),
                               BN_CTX *ctx, void *cb_arg))
DEPRECATEDIN_0_9_8(int
                   BN_is_prime_fasttest(const BIGNUMX *p, int nchecks,
                                        void (*callback) (int, int, void *),
                                        BN_CTX *ctx, void *cb_arg,
                                        int do_trial_division))

/* Newer versions */
int BNY_generate_prime_ex(BIGNUMX *ret, int bits, int safe, const BIGNUMX *add,
                         const BIGNUMX *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUMX *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BNY_is_prime_fasttest_ex(const BIGNUMX *p, int nchecks, BN_CTX *ctx,
                            int do_trial_division, BN_GENCB *cb);

int BN_X931_generate_Xpq(BIGNUMX *Xp, BIGNUMX *Xq, int nbits, BN_CTX *ctx);

int BN_X931_derive_prime_ex(BIGNUMX *p, BIGNUMX *p1, BIGNUMX *p2,
                            const BIGNUMX *Xp, const BIGNUMX *Xp1,
                            const BIGNUMX *Xp2, const BIGNUMX *e, BN_CTX *ctx,
                            BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUMX *p, BIGNUMX *p1, BIGNUMX *p2, BIGNUMX *Xp1,
                              BIGNUMX *Xp2, const BIGNUMX *Xp, const BIGNUMX *e,
                              BN_CTX *ctx, BN_GENCB *cb);

BN_MONT_CTX *BN_MONT_CTX_new(void);
int BNY_mod_mul_montgomery(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_to_montgomery(BIGNUMX *r, const BIGNUMX *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx);
int BN_from_montgomery(BIGNUMX *r, const BIGNUMX *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUMX *mod, BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
                                    const BIGNUMX *mod, BN_CTX *ctx);

/* BN_BLINDING flags */
# define BN_BLINDING_NO_UPDATE   0x00000001
# define BN_BLINDING_NO_RECREATE 0x00000002

BN_BLINDING *BN_BLINDING_new(const BIGNUMX *A, const BIGNUMX *Ai, BIGNUMX *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUMX *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUMX *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUMX *n, BIGNUMX *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUMX *n, const BIGNUMX *r, BN_BLINDING *b,
                          BN_CTX *);

int BN_BLINDING_is_current_thread(BN_BLINDING *b);
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
int BN_BLINDING_lock(BN_BLINDING *b);
int BN_BLINDING_unlock(BN_BLINDING *b);

unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUMX *e, BIGNUMX *m, BN_CTX *ctx,
                                      int (*bn_mod_exp) (BIGNUMX *r,
                                                         const BIGNUMX *a,
                                                         const BIGNUMX *p,
                                                         const BIGNUMX *m,
                                                         BN_CTX *ctx,
                                                         BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx);

DEPRECATEDIN_0_9_8(void BN_set_params(int mul, int high, int low, int mont))
DEPRECATEDIN_0_9_8(int BN_get_params(int which)) /* 0, mul, 1 high, 2 low, 3
                                                  * mont */

BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUMX *rdiv, BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUMX *r, const BIGNUMX *x, const BIGNUMX *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
                    const BIGNUMX *m, BN_CTX *ctx);
int BNY_div_recp(BIGNUMX *dv, BIGNUMX *rem, const BIGNUMX *m,
                BN_RECP_CTX *recp, BN_CTX *ctx);

# ifndef OPENSSL_NO_EC2M

/*
 * Functions for arithmetic over binary polynomials represented by BIGNUMXs.
 * The BIGNUMX::neg property of BIGNUMXs representing binary polynomials is
 * ignored. Note that input arguments are not const so that their bit arrays
 * can be expanded to the appropriate size if needed.
 */

/*
 * r = a + b
 */
int BN_GF2m_add(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b);
#  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
/*
 * r=a mod p
 */
int BN_GF2m_mod(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p);
/* r = (a * b) mod p */
int BN_GF2m_mod_mul(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                    const BIGNUMX *p, BN_CTX *ctx);
/* r = (a * a) mod p */
int BN_GF2m_mod_sqr(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);
/* r = (1 / b) mod p */
int BN_GF2m_mod_inv(BIGNUMX *r, const BIGNUMX *b, const BIGNUMX *p, BN_CTX *ctx);
/* r = (a / b) mod p */
int BN_GF2m_mod_div(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                    const BIGNUMX *p, BN_CTX *ctx);
/* r = (a ^ b) mod p */
int BN_GF2m_mod_exp(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                    const BIGNUMX *p, BN_CTX *ctx);
/* r = sqrt(a) mod p */
int BN_GF2m_mod_sqrt(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
                     BN_CTX *ctx);
/* r^2 + r = a mod p */
int BN_GF2m_mod_solve_quad(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
                           BN_CTX *ctx);
#  define BN_GF2m_cmp(a, b) BNY_ucmp((a), (b))
/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
/* r = a mod p */
int BN_GF2m_mod_arr(BIGNUMX *r, const BIGNUMX *a, const int p[]);
/* r = (a * b) mod p */
int BN_GF2m_mod_mul_arr(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                        const int p[], BN_CTX *ctx);
/* r = (a * a) mod p */
int BN_GF2m_mod_sqr_arr(BIGNUMX *r, const BIGNUMX *a, const int p[],
                        BN_CTX *ctx);
/* r = (1 / b) mod p */
int BN_GF2m_mod_inv_arr(BIGNUMX *r, const BIGNUMX *b, const int p[],
                        BN_CTX *ctx);
/* r = (a / b) mod p */
int BN_GF2m_mod_div_arr(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                        const int p[], BN_CTX *ctx);
/* r = (a ^ b) mod p */
int BN_GF2m_mod_exp_arr(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                        const int p[], BN_CTX *ctx);
/* r = sqrt(a) mod p */
int BN_GF2m_mod_sqrt_arr(BIGNUMX *r, const BIGNUMX *a,
                         const int p[], BN_CTX *ctx);
/* r^2 + r = a mod p */
int BN_GF2m_mod_solve_quad_arr(BIGNUMX *r, const BIGNUMX *a,
                               const int p[], BN_CTX *ctx);
int BN_GF2m_poly2arr(const BIGNUMX *a, int p[], int max);
int BN_GF2m_arr2poly(const int p[], BIGNUMX *a);

# endif

/*
 * faster mod functions for the 'NIST primes' 0 <= a < p^2
 */
int BN_nist_mod_192(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p, BN_CTX *ctx);

const BIGNUMX *BN_get0_nist_prime_192(void);
const BIGNUMX *BN_get0_nist_prime_224(void);
const BIGNUMX *BN_get0_nist_prime_256(void);
const BIGNUMX *BN_get0_nist_prime_384(void);
const BIGNUMX *BN_get0_nist_prime_521(void);

int (*BN_nist_mod_func(const BIGNUMX *p)) (BIGNUMX *r, const BIGNUMX *a,
                                          const BIGNUMX *field, BN_CTX *ctx);

int BN_generate_dsa_nonce(BIGNUMX *out, const BIGNUMX *range,
                          const BIGNUMX *priv, const unsigned char *message,
                          size_t message_len, BN_CTX *ctx);

/* Primes from RFC 2409 */
BIGNUMX *BN_get_rfc2409_prime_768(BIGNUMX *bn);
BIGNUMX *BN_get_rfc2409_prime_1024(BIGNUMX *bn);

/* Primes from RFC 3526 */
BIGNUMX *BN_get_rfc3526_prime_1536(BIGNUMX *bn);
BIGNUMX *BN_get_rfc3526_prime_2048(BIGNUMX *bn);
BIGNUMX *BN_get_rfc3526_prime_3072(BIGNUMX *bn);
BIGNUMX *BN_get_rfc3526_prime_4096(BIGNUMX *bn);
BIGNUMX *BN_get_rfc3526_prime_6144(BIGNUMX *bn);
BIGNUMX *BN_get_rfc3526_prime_8192(BIGNUMX *bn);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define get_rfc2409_prime_768 BN_get_rfc2409_prime_768
#  define get_rfc2409_prime_1024 BN_get_rfc2409_prime_1024
#  define get_rfc3526_prime_1536 BN_get_rfc3526_prime_1536
#  define get_rfc3526_prime_2048 BN_get_rfc3526_prime_2048
#  define get_rfc3526_prime_3072 BN_get_rfc3526_prime_3072
#  define get_rfc3526_prime_4096 BN_get_rfc3526_prime_4096
#  define get_rfc3526_prime_6144 BN_get_rfc3526_prime_6144
#  define get_rfc3526_prime_8192 BN_get_rfc3526_prime_8192
# endif

int BN_bntest_rand(BIGNUMX *rnd, int bits, int top, int bottom);


# ifdef  __cplusplus
}
# endif
#endif
