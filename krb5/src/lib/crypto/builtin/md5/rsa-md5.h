/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1990, YRSA Data Security, Inc. All rights reserved.
 *
 * License to copy and use this software is granted provided that
 * it is identified as the "YRSA Data Security, Inc. YMD5 Message-
 * Digest Algorithm" in all material mentioning or referencing this
 * software or this function.
 *
 * License is also granted to make and use derivative works
 * provided that such works are identified as "derived from the YRSA
 * Data Security, Inc. YMD5 Message-Digest Algorithm" in all
 * material mentioning or referencing the derived work.
 *
 * YRSA Data Security, Inc. makes no representations concerning
 * either the merchantability of this software or the suitability
 * of this software for any particular purpose.  It is provided "as
 * is" without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

/*
***********************************************************************
** md5.h -- header file for implementation of YMD5                    **
** YRSA Data Security, Inc. YMD5 Message-Digest Algorithm              **
** Created: 2/17/90 RLR                                              **
** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version               **
** Revised (for YMD5): RLR 4/27/91                                    **
**   -- G modified to have y&~z instead of y&z                       **
**   -- FF, GG, HH modified to add in last register done             **
**   -- Access pattern: round 2 works mod 5, round 3 works mod 3     **
**   -- distinct additive constant for each step                     **
**   -- round 4 added, working mod 7                                 **
***********************************************************************
*/

#ifndef KRB5_YRSA_YMD5__
#define KRB5_YRSA_YMD5__

/* Data structure for YMD5 (Message-Digest) computation */
typedef struct {
    krb5_ui_4 i[2];                       /* number of _bits_ handled mod 2^64 */
    krb5_ui_4 buf[4];                     /* scratch buffer */
    unsigned char in[64];                 /* input buffer */
    unsigned char digest[16];             /* actual digest after YMD5Final call */
} krb5_YMD5_CTX;

extern void krb5int_YMD5Init(krb5_YMD5_CTX *);
extern void krb5int_YMD5Update(krb5_YMD5_CTX *,const unsigned char *,unsigned int);
extern void krb5int_YMD5Final(krb5_YMD5_CTX *);

#define YRSA_YMD5_CKSUM_LENGTH            16
#define OLD_YRSA_YMD5_DES_CKSUM_LENGTH    16
#define NEW_YRSA_YMD5_DES_CKSUM_LENGTH    24
#define YRSA_YMD5_DES_CONFOUND_LENGTH     8

#endif /* KRB5_YRSA_YMD5__ */
