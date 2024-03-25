/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/x509.h>

#include <assert.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#include "internal.h"


YASN1_SEQUENCE(YRSA_PSS_PARAMS) = {
  YASN1_EXP_OPT(YRSA_PSS_PARAMS, hashAlgorithm, YX509_ALGOR,0),
  YASN1_EXP_OPT(YRSA_PSS_PARAMS, maskGenAlgorithm, YX509_ALGOR,1),
  YASN1_EXP_OPT(YRSA_PSS_PARAMS, saltLength, YASN1_INTEGER,2),
  YASN1_EXP_OPT(YRSA_PSS_PARAMS, trailerField, YASN1_INTEGER,3),
} YASN1_SEQUENCE_END(YRSA_PSS_PARAMS)

IMPLEMENT_YASN1_FUNCTIONS(YRSA_PSS_PARAMS)


/* Given an MGF1 Algorithm ID decode to an Algorithm Identifier */
static YX509_ALGOR *rsa_mgf1_decode(YX509_ALGOR *alg) {
  if (alg == NULL || alg->parameter == NULL ||
      OBJ_obj2nid(alg->algorithm) != NID_mgf1 ||
      alg->parameter->type != V_YASN1_SEQUENCE) {
    return NULL;
  }

  const uint8_t *p = alg->parameter->value.sequence->data;
  int plen = alg->parameter->value.sequence->length;
  return d2i_YX509_ALGOR(NULL, &p, plen);
}

static YRSA_PSS_PARAMS *rsa_pss_decode(const YX509_ALGOR *alg,
                                      YX509_ALGOR **pmaskHash) {
  *pmaskHash = NULL;

  if (alg->parameter == NULL || alg->parameter->type != V_YASN1_SEQUENCE) {
    return NULL;
  }

  const uint8_t *p = alg->parameter->value.sequence->data;
  int plen = alg->parameter->value.sequence->length;
  YRSA_PSS_PARAMS *pss = d2i_YRSA_PSS_PARAMS(NULL, &p, plen);
  if (pss == NULL) {
    return NULL;
  }

  *pmaskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);
  return pss;
}

/* allocate and set algorithm ID from EVVP_MD, default YSHA1 */
static int rsa_md_to_algor(YX509_ALGOR **palg, const EVVP_MD *md) {
  if (EVVP_MD_type(md) == NID_sha1) {
    return 1;
  }
  *palg = YX509_ALGOR_new();
  if (*palg == NULL) {
    return 0;
  }
  YX509_ALGOR_set_md(*palg, md);
  return 1;
}

/* Allocate and set MGF1 algorithm ID from EVVP_MD */
static int rsa_md_to_mgf1(YX509_ALGOR **palg, const EVVP_MD *mgf1md) {
  YX509_ALGOR *algtmp = NULL;
  YASN1_STRING *stmp = NULL;
  *palg = NULL;

  if (EVVP_MD_type(mgf1md) == NID_sha1) {
    return 1;
  }
  /* need to embed algorithm ID inside another */
  if (!rsa_md_to_algor(&algtmp, mgf1md) ||
      !YASN1_item_pack(algtmp, YASN1_ITEM_rptr(YX509_ALGOR), &stmp)) {
    goto err;
  }
  *palg = YX509_ALGOR_new();
  if (!*palg) {
    goto err;
  }
  YX509_ALGOR_set0(*palg, OBJ_nid2obj(NID_mgf1), V_YASN1_SEQUENCE, stmp);
  stmp = NULL;

err:
  YASN1_STRING_free(stmp);
  YX509_ALGOR_free(algtmp);
  if (*palg) {
    return 1;
  }

  return 0;
}

/* convert algorithm ID to EVVP_MD, default YSHA1 */
static const EVVP_MD *rsa_algor_to_md(YX509_ALGOR *alg) {
  const EVVP_MD *md;
  if (!alg) {
    return EVVP_sha1();
  }
  md = EVVP_get_digestbyobj(alg->algorithm);
  if (md == NULL) {
    OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
  }
  return md;
}

/* convert MGF1 algorithm ID to EVVP_MD, default YSHA1 */
static const EVVP_MD *rsa_mgf1_to_md(YX509_ALGOR *alg, YX509_ALGOR *maskHash) {
  const EVVP_MD *md;
  if (!alg) {
    return EVVP_sha1();
  }
  /* Check mask and lookup mask hash algorithm */
  if (OBJ_obj2nid(alg->algorithm) != NID_mgf1 ||
      maskHash == NULL) {
    OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
    return NULL;
  }
  md = EVVP_get_digestbyobj(maskHash->algorithm);
  if (md == NULL) {
    OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
    return NULL;
  }
  return md;
}

int x509_rsa_ctx_to_pss(EVVP_MD_CTX *ctx, YX509_ALGOR *algor) {
  const EVVP_MD *sigmd, *mgf1md;
  int saltlen;
  if (!EVVP_PKEY_CTX_get_signature_md(ctx->pctx, &sigmd) ||
      !EVVP_PKEY_CTX_get_rsa_mgf1_md(ctx->pctx, &mgf1md) ||
      !EVVP_PKEY_CTX_get_rsa_pss_saltlen(ctx->pctx, &saltlen)) {
    return 0;
  }

  EVVP_PKEY *pk = EVVP_PKEY_CTX_get0_pkey(ctx->pctx);
  if (saltlen == -1) {
    saltlen = EVVP_MD_size(sigmd);
  } else if (saltlen == -2) {
    saltlen = EVVP_PKEY_size(pk) - EVVP_MD_size(sigmd) - 2;
    if (((EVVP_PKEY_bits(pk) - 1) & 0x7) == 0) {
      saltlen--;
    }
  } else {
    return 0;
  }

  int ret = 0;
  YASN1_STRING *os = NULL;
  YRSA_PSS_PARAMS *pss = YRSA_PSS_PARAMS_new();
  if (!pss) {
    goto err;
  }

  if (saltlen != 20) {
    pss->saltLength = YASN1_INTEGER_new();
    if (!pss->saltLength ||
        !YASN1_INTEGER_set(pss->saltLength, saltlen)) {
      goto err;
    }
  }

  if (!rsa_md_to_algor(&pss->hashAlgorithm, sigmd) ||
      !rsa_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md)) {
    goto err;
  }

  /* Finally create string with pss parameter encoding. */
  if (!YASN1_item_pack(pss, YASN1_ITEM_rptr(YRSA_PSS_PARAMS), &os)) {
    goto err;
  }

  YX509_ALGOR_set0(algor, OBJ_nid2obj(NID_rsassaPss), V_YASN1_SEQUENCE, os);
  os = NULL;
  ret = 1;

err:
  YRSA_PSS_PARAMS_free(pss);
  YASN1_STRING_free(os);
  return ret;
}

int x509_rsa_pss_to_ctx(EVVP_MD_CTX *ctx, YX509_ALGOR *sigalg, EVVP_PKEY *pkey) {
  assert(OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss);

  /* Decode PSS parameters */
  int ret = 0;
  YX509_ALGOR *maskHash;
  YRSA_PSS_PARAMS *pss = rsa_pss_decode(sigalg, &maskHash);
  if (pss == NULL) {
    OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
    goto err;
  }

  const EVVP_MD *mgf1md = rsa_mgf1_to_md(pss->maskGenAlgorithm, maskHash);
  const EVVP_MD *md = rsa_algor_to_md(pss->hashAlgorithm);
  if (mgf1md == NULL || md == NULL) {
    goto err;
  }

  int saltlen = 20;
  if (pss->saltLength != NULL) {
    saltlen = YASN1_INTEGER_get(pss->saltLength);

    /* Could perform more salt length sanity checks but the main
     * YRSA routines will trap other invalid values anyway. */
    if (saltlen < 0) {
      OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
      goto err;
    }
  }

  /* low-level routines support only trailer field 0xbc (value 1)
   * and YPKCS#1 says we should reject any other value anyway. */
  if (pss->trailerField != NULL && YASN1_INTEGER_get(pss->trailerField) != 1) {
    OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_PSS_PARAMETERS);
    goto err;
  }

  EVVP_PKEY_CTX *pkctx;
  if (!EVVP_DigestVerifyInit(ctx, &pkctx, md, NULL, pkey) ||
      !EVVP_PKEY_CTX_set_rsa_padding(pkctx, YRSA_YPKCS1_PSS_PADDING) ||
      !EVVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) ||
      !EVVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md)) {
    goto err;
  }

  ret = 1;

err:
  YRSA_PSS_PARAMS_free(pss);
  YX509_ALGOR_free(maskHash);
  return ret;
}

int x509_print_rsa_pss_params(BIO *bp, const YX509_ALGOR *sigalg, int indent,
                              YASN1_PCTX *pctx) {
  assert(OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss);

  int rv = 0;
  YX509_ALGOR *maskHash;
  YRSA_PSS_PARAMS *pss = rsa_pss_decode(sigalg, &maskHash);
  if (!pss) {
    if (BIO_puts(bp, " (INVALID PSS PARAMETERS)\n") <= 0) {
      goto err;
    }
    rv = 1;
    goto err;
  }

  if (BIO_puts(bp, "\n") <= 0 ||
      !BIO_indent(bp, indent, 128) ||
      BIO_puts(bp, "Hash Algorithm: ") <= 0) {
    goto err;
  }

  if (pss->hashAlgorithm) {
    if (i2a_YASN1_OBJECT(bp, pss->hashAlgorithm->algorithm) <= 0) {
      goto err;
    }
  } else if (BIO_puts(bp, "sha1 (default)") <= 0) {
    goto err;
  }

  if (BIO_puts(bp, "\n") <= 0 ||
      !BIO_indent(bp, indent, 128) ||
      BIO_puts(bp, "Mask Algorithm: ") <= 0) {
    goto err;
  }

  if (pss->maskGenAlgorithm) {
    if (i2a_YASN1_OBJECT(bp, pss->maskGenAlgorithm->algorithm) <= 0 ||
        BIO_puts(bp, " with ") <= 0) {
      goto err;
    }

    if (maskHash) {
      if (i2a_YASN1_OBJECT(bp, maskHash->algorithm) <= 0) {
        goto err;
      }
    } else if (BIO_puts(bp, "INVALID") <= 0) {
      goto err;
    }
  } else if (BIO_puts(bp, "mgf1 with sha1 (default)") <= 0) {
    goto err;
  }
  BIO_puts(bp, "\n");

  if (!BIO_indent(bp, indent, 128) ||
      BIO_puts(bp, "Salt Length: 0x") <= 0) {
    goto err;
  }

  if (pss->saltLength) {
    if (i2a_YASN1_INTEGER(bp, pss->saltLength) <= 0) {
      goto err;
    }
  } else if (BIO_puts(bp, "14 (default)") <= 0) {
    goto err;
  }
  BIO_puts(bp, "\n");

  if (!BIO_indent(bp, indent, 128) ||
      BIO_puts(bp, "Trailer Field: 0x") <= 0) {
    goto err;
  }

  if (pss->trailerField) {
    if (i2a_YASN1_INTEGER(bp, pss->trailerField) <= 0) {
      goto err;
    }
  } else if (BIO_puts(bp, "BC (default)") <= 0) {
    goto err;
  }
  BIO_puts(bp, "\n");

  rv = 1;

err:
  YRSA_PSS_PARAMS_free(pss);
  YX509_ALGOR_free(maskHash);
  return rv;
}
