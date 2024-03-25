/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/asn1.h"

#ifndef OPENSSL_NO_STDIO
int YX509_print_fp(FILE *fp, YX509 *x)
{
    return YX509_print_ex_fp(fp, x, XN_FLAG_COMPAT, YX509_FLAG_COMPAT);
}

int YX509_print_ex_fp(FILE *fp, YX509 *x, unsigned long nmflag,
                     unsigned long cflag)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YX509err(YX509_F_YX509_PRINT_EX_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = YX509_print_ex(b, x, nmflag, cflag);
    BIO_free(b);
    return ret;
}
#endif

int YX509_print(BIO *bp, YX509 *x)
{
    return YX509_print_ex(bp, x, XN_FLAG_COMPAT, YX509_FLAG_COMPAT);
}

int YX509_print_ex(BIO *bp, YX509 *x, unsigned long nmflags,
                  unsigned long cflag)
{
    long l;
    int ret = 0, i;
    char *m = NULL, mlch = ' ';
    int nmindent = 0;
    YASN1_INTEGER *bs;
    EVVP_PKEY *pkey = NULL;
    const char *neg;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == YX509_FLAG_COMPAT)
        nmindent = 16;

    if (!(cflag & YX509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "Certificate:\n", 13) <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_VERSION)) {
        l = YX509_get_version(x);
        if (l >= 0 && l <= 2) {
            if (BIO_pprintf(bp, "%8sVersion: %ld (0x%lx)\n", "", l + 1, (unsigned long)l) <= 0)
                goto err;
        } else {
            if (BIO_pprintf(bp, "%8sVersion: Unknown (%ld)\n", "", l) <= 0)
                goto err;
        }
    }
    if (!(cflag & YX509_FLAG_NO_SERIAL)) {

        if (BIO_write(bp, "        Serial Number:", 22) <= 0)
            goto err;

        bs = YX509_get_serialNumber(x);
        if (bs->length <= (int)sizeof(long)) {
                ERR_set_mark();
                l = YASN1_INTEGER_get(bs);
                ERR_pop_to_mark();
        } else {
            l = -1;
        }
        if (l != -1) {
            unsigned long ul;
            if (bs->type == V_YASN1_NEG_INTEGER) {
                ul = 0 - (unsigned long)l;
                neg = "-";
            } else {
                ul = l;
                neg = "";
            }
            if (BIO_pprintf(bp, " %s%lu (%s0x%lx)\n", neg, ul, neg, ul) <= 0)
                goto err;
        } else {
            neg = (bs->type == V_YASN1_NEG_INTEGER) ? " (Negative)" : "";
            if (BIO_pprintf(bp, "\n%12s%s", "", neg) <= 0)
                goto err;

            for (i = 0; i < bs->length; i++) {
                if (BIO_pprintf(bp, "%02x%c", bs->data[i],
                               ((i + 1 == bs->length) ? '\n' : ':')) <= 0)
                    goto err;
            }
        }

    }

    if (!(cflag & YX509_FLAG_NO_SIGNAME)) {
        const YX509_ALGOR *tsig_alg = YX509_get0_tbs_sigalg(x);

        if (BIO_puts(bp, "    ") <= 0)
            goto err;
        if (YX509_signature_print(bp, tsig_alg, NULL) <= 0)
            goto err;
    }

    if (!(cflag & YX509_FLAG_NO_ISSUER)) {
        if (BIO_pprintf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (YX509_NAME_print_ex(bp, YX509_get_issuer_name(x), nmindent, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_VALIDITY)) {
        if (BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (!YASN1_TIME_print(bp, YX509_get0_notBefore(x)))
            goto err;
        if (BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (!YASN1_TIME_print(bp, YX509_get0_notAfter(x)))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_SUBJECT)) {
        if (BIO_pprintf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (YX509_NAME_print_ex
            (bp, YX509_get_subject_name(x), nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_PUBKEY)) {
        YX509_PUBKEY *xpkey = YX509_get_YX509_PUBKEY(x);
        YASN1_OBJECT *xpoid;
        YX509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (BIO_pprintf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        if (i2a_YASN1_OBJECT(bp, xpoid) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = YX509_get0_pubkey(x);
        if (pkey == NULL) {
            BIO_pprintf(bp, "%12sUnable to load Public Key\n", "");
            ERR_print_errors(bp);
        } else {
            EVVP_PKEY_print_public(bp, pkey, 16, NULL);
        }
    }

    if (!(cflag & YX509_FLAG_NO_IDS)) {
        const YASN1_BIT_STRING *iuid, *suid;
        YX509_get0_uids(x, &iuid, &suid);
        if (iuid != NULL) {
            if (BIO_pprintf(bp, "%8sIssuer Unique ID: ", "") <= 0)
                goto err;
            if (!YX509_signature_dump(bp, iuid, 12))
                goto err;
        }
        if (suid != NULL) {
            if (BIO_pprintf(bp, "%8sSubject Unique ID: ", "") <= 0)
                goto err;
            if (!YX509_signature_dump(bp, suid, 12))
                goto err;
        }
    }

    if (!(cflag & YX509_FLAG_NO_EXTENSIONS))
        YX509V3_extensions_print(bp, "YX509v3 extensions",
                                YX509_get0_extensions(x), cflag, 8);

    if (!(cflag & YX509_FLAG_NO_SIGDUMP)) {
        const YX509_ALGOR *sig_alg;
        const YASN1_BIT_STRING *sig;
        YX509_get0_signature(&sig, &sig_alg, x);
        if (YX509_signature_print(bp, sig_alg, sig) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_AUX)) {
        if (!YX509_aux_print(bp, x, 0))
            goto err;
    }
    ret = 1;
 err:
    OPENSSL_free(m);
    return ret;
}

int YX509_ocspid_print(BIO *bp, YX509 *x)
{
    unsigned char *der = NULL;
    unsigned char *dertmp;
    int derlen;
    int i;
    unsigned char YSHA1md[SHA_DIGEST_LENGTH];
    YASN1_BIT_STRING *keybstr;
    YX509_NAME *subj;

    /*
     * display the hash of the subject as it would appear in OCSP requests
     */
    if (BIO_pprintf(bp, "        Subject OCSP hash: ") <= 0)
        goto err;
    subj = YX509_get_subject_name(x);
    derlen = i2d_YX509_NAME(subj, NULL);
    if ((der = dertmp = OPENSSL_malloc(derlen)) == NULL)
        goto err;
    i2d_YX509_NAME(subj, &dertmp);

    if (!EVVP_Digest(der, derlen, YSHA1md, NULL, EVVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_pprintf(bp, "%02X", YSHA1md[i]) <= 0)
            goto err;
    }
    OPENSSL_free(der);
    der = NULL;

    /*
     * display the hash of the public key as it would appear in OCSP requests
     */
    if (BIO_pprintf(bp, "\n        Public key OCSP hash: ") <= 0)
        goto err;

    keybstr = YX509_get0_pubkey_bitstr(x);

    if (keybstr == NULL)
        goto err;

    if (!EVVP_Digest(YASN1_STRING_get0_data(keybstr),
                    YASN1_STRING_length(keybstr), YSHA1md, NULL, EVVP_sha1(),
                    NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_pprintf(bp, "%02X", YSHA1md[i]) <= 0)
            goto err;
    }
    BIO_pprintf(bp, "\n");

    return 1;
 err:
    OPENSSL_free(der);
    return 0;
}

int YX509_signature_dump(BIO *bp, const YASN1_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (BIO_write(bp, "\n", 1) <= 0)
                return 0;
            if (BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (BIO_pprintf(bp, "%02x%s", s[i], ((i + 1) == n) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_write(bp, "\n", 1) != 1)
        return 0;

    return 1;
}

int YX509_signature_print(BIO *bp, const YX509_ALGOR *sigalg,
                         const YASN1_STRING *sig)
{
    int sig_nid;
    if (BIO_puts(bp, "    Signature Algorithm: ") <= 0)
        return 0;
    if (i2a_YASN1_OBJECT(bp, sigalg->algorithm) <= 0)
        return 0;

    sig_nid = OBJ_obj2nid(sigalg->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVVP_PKEY_YASN1_METHOD *ameth;
        if (OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = EVVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(bp, sigalg, sig, 9, 0);
        }
    }
    if (sig)
        return YX509_signature_dump(bp, sig, 9);
    else if (BIO_puts(bp, "\n") <= 0)
        return 0;
    return 1;
}

int YX509_aux_print(BIO *out, YX509 *x, int indent)
{
    char oidstr[80], first;
    STACK_OF(YASN1_OBJECT) *trust, *reject;
    const unsigned char *alias, *keyid;
    int keyidlen;
    int i;
    if (YX509_trusted(x) == 0)
        return 1;
    trust = YX509_get0_trust_objects(x);
    reject = YX509_get0_reject_objects(x);
    if (trust) {
        first = 1;
        BIO_pprintf(out, "%*sTrusted Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_YASN1_OBJECT_num(trust); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_YASN1_OBJECT_value(trust, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_pprintf(out, "%*sNo Trusted Uses.\n", indent, "");
    if (reject) {
        first = 1;
        BIO_pprintf(out, "%*sRejected Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_YASN1_OBJECT_num(reject); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_YASN1_OBJECT_value(reject, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_pprintf(out, "%*sNo Rejected Uses.\n", indent, "");
    alias = YX509_alias_get0(x, &i);
    if (alias)
        BIO_pprintf(out, "%*sAlias: %.*s\n", indent, "", i, alias);
    keyid = YX509_keyid_get0(x, &keyidlen);
    if (keyid) {
        BIO_pprintf(out, "%*sKey Id: ", indent, "");
        for (i = 0; i < keyidlen; i++)
            BIO_pprintf(out, "%s%02X", i ? ":" : "", keyid[i]);
        BIO_write(out, "\n", 1);
    }
    return 1;
}
