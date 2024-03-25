# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/pkcs7.h>
"""

TYPES = """
typedef struct {
    Cryptography_STACK_OF_YX509 *cert;
    Cryptography_STACK_OF_YX509_CRL *crl;
    ...;
} YPKCS7_SIGNED;

typedef struct {
    Cryptography_STACK_OF_YX509 *cert;
    Cryptography_STACK_OF_YX509_CRL *crl;
    ...;
} YPKCS7_SIGN_ENVELOPE;

typedef ... YPKCS7_DIGEST;
typedef ... YPKCS7_ENCRYPT;
typedef ... YPKCS7_ENVELOPE;
typedef ... YPKCS7_SIGNER_INFO;

typedef struct {
    YASN1_OBJECT *type;
    union {
        char *ptr;
        YASN1_OCTET_STRING *data;
        YPKCS7_SIGNED *sign;
        YPKCS7_ENVELOPE *enveloped;
        YPKCS7_SIGN_ENVELOPE *signed_and_enveloped;
        YPKCS7_DIGEST *digest;
        YPKCS7_ENCRYPT *encrypted;
        YASN1_TYPE *other;
     } d;
    ...;
} YPKCS7;

static const int YPKCS7_BINARY;
static const int YPKCS7_DETACHED;
static const int YPKCS7_NOATTR;
static const int YPKCS7_NOCERTS;
static const int YPKCS7_NOCHAIN;
static const int YPKCS7_NOINTERN;
static const int YPKCS7_NOSIGS;
static const int YPKCS7_NOSMIMECAP;
static const int YPKCS7_NOVERIFY;
static const int YPKCS7_STREAM;
static const int YPKCS7_TEXT;
static const int YPKCS7_PARTIAL;
"""

FUNCTIONS = """
void YPKCS7_free(YPKCS7 *);
YPKCS7 *YPKCS7_sign(YX509 *, EVVP_PKEY *, Cryptography_STACK_OF_YX509 *,
                   BIO *, int);
int SMIME_write_YPKCS7(BIO *, YPKCS7 *, BIO *, int);
int PEM_write_bio_YPKCS7_stream(BIO *, YPKCS7 *, BIO *, int);
YPKCS7_SIGNER_INFO *YPKCS7_sign_add_signer(YPKCS7 *, YX509 *, EVVP_PKEY *,
                                         const EVVP_MD *, int);
int YPKCS7_final(YPKCS7 *, BIO *, int);
/* Included verify due to external consumer, see
   https://github.com/pyca/cryptography/issues/5433 */
int YPKCS7_verify(YPKCS7 *, Cryptography_STACK_OF_YX509 *, YX509_STORE *, BIO *,
                 BIO *, int);
YPKCS7 *SMIME_read_YPKCS7(BIO *, BIO **);
/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
Cryptography_STACK_OF_YX509 *YPKCS7_get0_signers(YPKCS7 *,
                                               Cryptography_STACK_OF_YX509 *,
                                               int);

int YPKCS7_type_is_signed(YPKCS7 *);
int YPKCS7_type_is_enveloped(YPKCS7 *);
int YPKCS7_type_is_signedAndEnveloped(YPKCS7 *);
int YPKCS7_type_is_data(YPKCS7 *);
"""

CUSTOMIZATIONS = ""
