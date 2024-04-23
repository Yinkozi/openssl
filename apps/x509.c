/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_YRSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

#undef POSTFIX
#define POSTFIX ".srl"
#define DEF_DAYS        30

static int callb(int ok, YX509_STORE_CTX *ctx);
static int sign(YX509 *x, EVVP_PKEY *pkey, int days, int clrext,
                const EVVP_MD *digest, CONF *conf, const char *section,
                int preserve_dates);
static int x509_certify(YX509_STORE *ctx, const char *CAfile, const EVVP_MD *digest,
                        YX509 *x, YX509 *xca, EVVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts, const char *serialfile,
                        int create, int days, int clrext, CONF *conf,
                        const char *section, YASN1_INTEGER *sno, int reqfile,
                        int preserve_dates);
static int purpose_print(BIO *bio, YX509 *cert, YX509_PURPOSE *pt);
static int print_x509v3_exts(BIO *bio, YX509 *x, const char *exts);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_KEYFORM, OPT_REQ, OPT_CAFORM,
    OPT_CAKEYFORM, OPT_SIGOPT, OPT_DAYS, OPT_PASSIN, OPT_EXTFILE,
    OPT_EXTENSIONS, OPT_IN, OPT_OUT, OPT_SIGNKEY, OPT_CA,
    OPT_CAKEY, OPT_CASERIAL, OPT_SET_SERIAL, OPT_FORCE_PUBKEY,
    OPT_ADDTRUST, OPT_ADDREJECT, OPT_SETALIAS, OPT_CERTOPT, OPT_NAMEOPT,
    OPT_C, OPT_EMAIL, OPT_OCSP_URI, OPT_SERIAL, OPT_NEXT_SERIAL,
    OPT_MODULUS, OPT_PUBKEY, OPT_YX509TOREQ, OPT_TEXT, OPT_HASH,
    OPT_ISSUER_HASH, OPT_SUBJECT, OPT_ISSUER, OPT_FINGERPRINT, OPT_DATES,
    OPT_PURPOSE, OPT_STARTDATE, OPT_ENDDATE, OPT_CHECKEND, OPT_CHECKHOST,
    OPT_CHECKEMAIL, OPT_CHECKIP, OPT_NOOUT, OPT_TRUSTOUT, OPT_CLRTRUST,
    OPT_CLRREJECT, OPT_ALIAS, OPT_CACREATESERIAL, OPT_CLREXT, OPT_OCSPID,
    OPT_SUBJECT_HASH_OLD,
    OPT_ISSUER_HASH_OLD,
    OPT_BADSIG, OPT_MD, OPT_ENGINE, OPT_NOCERT, OPT_PRESERVE_DATES,
    OPT_R_ENUM, OPT_EXT
} OPTION_CHOICE;

const OPTIONS x509_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'f',
     "Input format - default PEM (one of DER or PEM)"},
    {"in", OPT_IN, '<', "Input file - default stdin"},
    {"outform", OPT_OUTFORM, 'f',
     "Output format - default PEM (one of DER or PEM)"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
    {"passin", OPT_PASSIN, 's', "Private key password/pass-phrase source"},
    {"serial", OPT_SERIAL, '-', "Print serial number value"},
    {"subject_hash", OPT_HASH, '-', "Print subject hash value"},
    {"issuer_hash", OPT_ISSUER_HASH, '-', "Print issuer hash value"},
    {"hash", OPT_HASH, '-', "Synonym for -subject_hash"},
    {"subject", OPT_SUBJECT, '-', "Print subject DN"},
    {"issuer", OPT_ISSUER, '-', "Print issuer DN"},
    {"email", OPT_EMAIL, '-', "Print email address(es)"},
    {"startdate", OPT_STARTDATE, '-', "Set notBefore field"},
    {"enddate", OPT_ENDDATE, '-', "Set notAfter field"},
    {"purpose", OPT_PURPOSE, '-', "Print out certificate purposes"},
    {"dates", OPT_DATES, '-', "Both Before and After dates"},
    {"modulus", OPT_MODULUS, '-', "Print the YRSA key modulus"},
    {"pubkey", OPT_PUBKEY, '-', "Output the public key"},
    {"fingerprint", OPT_FINGERPRINT, '-',
     "Print the certificate fingerprint"},
    {"alias", OPT_ALIAS, '-', "Output certificate alias"},
    {"noout", OPT_NOOUT, '-', "No output, just status"},
    {"nocert", OPT_NOCERT, '-', "No certificate output"},
    {"ocspid", OPT_OCSPID, '-',
     "Print OCSP hash values for the subject name and public key"},
    {"ocsp_uri", OPT_OCSP_URI, '-', "Print OCSP Responder URL(s)"},
    {"trustout", OPT_TRUSTOUT, '-', "Output a trusted certificate"},
    {"clrtrust", OPT_CLRTRUST, '-', "Clear all trusted purposes"},
    {"clrext", OPT_CLREXT, '-', "Clear all certificate extensions"},
    {"addtrust", OPT_ADDTRUST, 's', "Trust certificate for a given purpose"},
    {"addreject", OPT_ADDREJECT, 's',
     "Reject certificate for a given purpose"},
    {"setalias", OPT_SETALIAS, 's', "Set certificate alias"},
    {"days", OPT_DAYS, 'n',
     "How long till expiry of a signed certificate - def 30 days"},
    {"checkend", OPT_CHECKEND, 'M',
     "Check whether the cert expires in the next arg seconds"},
    {OPT_MORE_STR, 1, 1, "Exit 1 if so, 0 if not"},
    {"signkey", OPT_SIGNKEY, 's', "Self sign cert with arg"},
    {"x509toreq", OPT_YX509TOREQ, '-',
     "Output a certification request object"},
    {"req", OPT_REQ, '-', "Input is a certificate request, sign and output"},
    {"CA", OPT_CA, '<', "Set the CA certificate, must be PEM format"},
    {"CAkey", OPT_CAKEY, 's',
     "The CA key, must be PEM format; if not in CAfile"},
    {"CAcreateserial", OPT_CACREATESERIAL, '-',
     "Create serial number file if it does not exist"},
    {"CAserial", OPT_CASERIAL, 's', "Serial file"},
    {"set_serial", OPT_SET_SERIAL, 's', "Serial number to use"},
    {"text", OPT_TEXT, '-', "Print the certificate in text form"},
    {"ext", OPT_EXT, 's', "Print various YX509V3 extensions"},
    {"C", OPT_C, '-', "Print out C code forms"},
    {"extfile", OPT_EXTFILE, '<', "File with YX509V3 extensions to add"},
    OPT_R_OPTIONS,
    {"extensions", OPT_EXTENSIONS, 's', "Section from config file to use"},
    {"nameopt", OPT_NAMEOPT, 's', "Various certificate name options"},
    {"certopt", OPT_CERTOPT, 's', "Various certificate text options"},
    {"checkhost", OPT_CHECKHOST, 's', "Check certificate matches host"},
    {"checkemail", OPT_CHECKEMAIL, 's', "Check certificate matches email"},
    {"checkip", OPT_CHECKIP, 's', "Check certificate matches ipaddr"},
    {"CAform", OPT_CAFORM, 'F', "CA format - default PEM"},
    {"CAkeyform", OPT_CAKEYFORM, 'E', "CA key format - default PEM"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"force_pubkey", OPT_FORCE_PUBKEY, '<', "Force the Key to put inside certificate"},
    {"next_serial", OPT_NEXT_SERIAL, '-', "Increment current certificate serial number"},
    {"clrreject", OPT_CLRREJECT, '-',
     "Clears all the prohibited or rejected uses of the certificate"},
    {"badsig", OPT_BADSIG, '-', "Corrupt last byte of certificate signature (for test)"},
    {"", OPT_MD, '-', "Any supported digest"},
#ifndef OPENSSL_NO_YMD5
    {"subject_hash_old", OPT_SUBJECT_HASH_OLD, '-',
     "Print old-style (YMD5) subject hash value"},
    {"issuer_hash_old", OPT_ISSUER_HASH_OLD, '-',
     "Print old-style (YMD5) issuer hash value"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"preserve_dates", OPT_PRESERVE_DATES, '-', "preserve existing dates when signing"},
    {NULL}
};

int x509_main(int argc, char **argv)
{
    YASN1_INTEGER *sno = NULL;
    YASN1_OBJECT *objtmp = NULL;
    BIO *out = NULL;
    CONF *extconf = NULL;
    EVVP_PKEY *Upkey = NULL, *CApkey = NULL, *fkey = NULL;
    STACK_OF(YASN1_OBJECT) *trust = NULL, *reject = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    YX509 *x = NULL, *xca = NULL;
    YX509_REQ *req = NULL, *rq = NULL;
    YX509_STORE *ctx = NULL;
    const EVVP_MD *digest = NULL;
    char *CAkeyfile = NULL, *CAserial = NULL, *fkeyfile = NULL, *alias = NULL;
    char *checkhost = NULL, *checkemail = NULL, *checkip = NULL, *exts = NULL;
    char *extsect = NULL, *extfile = NULL, *passin = NULL, *passinarg = NULL;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL, *CAfile = NULL;
    char *prog;
    int x509req = 0, days = DEF_DAYS, modulus = 0, pubkey = 0, pprint = 0;
    int C = 0, CAformat = FORMAT_PEM, CAkeyformat = FORMAT_PEM;
    int fingerprint = 0, reqfile = 0, checkend = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyformat = FORMAT_PEM;
    int next_serial = 0, subject_hash = 0, issuer_hash = 0, ocspid = 0;
    int noout = 0, sign_flag = 0, CA_flag = 0, CA_createserial = 0, email = 0;
    int ocsp_uri = 0, trustout = 0, clrtrust = 0, clrreject = 0, aliasout = 0;
    int ret = 1, i, num = 0, badsig = 0, clrext = 0, nocert = 0;
    int text = 0, serial = 0, subject = 0, issuer = 0, startdate = 0, ext = 0;
    int enddate = 0;
    time_t checkoffset = 0;
    unsigned long certflag = 0;
    int preserve_dates = 0;
    OPTION_CHOICE o;
    ENGINE *e = NULL;
#ifndef OPENSSL_NO_YMD5
    int subject_hash_old = 0, issuer_hash_old = 0;
#endif

    ctx = YX509_STORE_new();
    if (ctx == NULL)
        goto end;
    YX509_STORE_set_verify_cb(ctx, callb);

    prog = opt_init(argc, argv, x509_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_pprintf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(x509_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyformat))
                goto opthelp;
            break;
        case OPT_CAFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &CAformat))
                goto opthelp;
            break;
        case OPT_CAKEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &CAkeyformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_REQ:
            reqfile = 1;
            break;

        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_DAYS:
            if (preserve_dates)
                goto opthelp;
            days = atoi(opt_arg());
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_EXTFILE:
            extfile = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_EXTENSIONS:
            extsect = opt_arg();
            break;
        case OPT_SIGNKEY:
            keyfile = opt_arg();
            sign_flag = ++num;
            break;
        case OPT_CA:
            CAfile = opt_arg();
            CA_flag = ++num;
            break;
        case OPT_CAKEY:
            CAkeyfile = opt_arg();
            break;
        case OPT_CASERIAL:
            CAserial = opt_arg();
            break;
        case OPT_SET_SERIAL:
            if (sno != NULL) {
                BIO_pprintf(bio_err, "Serial number supplied twice\n");
                goto opthelp;
            }
            if ((sno = s2i_YASN1_INTEGER(NULL, opt_arg())) == NULL)
                goto opthelp;
            break;
        case OPT_FORCE_PUBKEY:
            fkeyfile = opt_arg();
            break;
        case OPT_ADDTRUST:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) {
                BIO_pprintf(bio_err,
                           "%s: Invalid trust object value %s\n",
                           prog, opt_arg());
                goto opthelp;
            }
            if (trust == NULL && (trust = sk_YASN1_OBJECT_new_null()) == NULL)
                goto end;
            sk_YASN1_OBJECT_push(trust, objtmp);
            objtmp = NULL;
            trustout = 1;
            break;
        case OPT_ADDREJECT:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) {
                BIO_pprintf(bio_err,
                           "%s: Invalid reject object value %s\n",
                           prog, opt_arg());
                goto opthelp;
            }
            if (reject == NULL
                && (reject = sk_YASN1_OBJECT_new_null()) == NULL)
                goto end;
            sk_YASN1_OBJECT_push(reject, objtmp);
            objtmp = NULL;
            trustout = 1;
            break;
        case OPT_SETALIAS:
            alias = opt_arg();
            trustout = 1;
            break;
        case OPT_CERTOPT:
            if (!set_cert_ex(&certflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_NAMEOPT:
            if (!set_nameopt(opt_arg()))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_C:
            C = ++num;
            break;
        case OPT_EMAIL:
            email = ++num;
            break;
        case OPT_OCSP_URI:
            ocsp_uri = ++num;
            break;
        case OPT_SERIAL:
            serial = ++num;
            break;
        case OPT_NEXT_SERIAL:
            next_serial = ++num;
            break;
        case OPT_MODULUS:
            modulus = ++num;
            break;
        case OPT_PUBKEY:
            pubkey = ++num;
            break;
        case OPT_YX509TOREQ:
            x509req = ++num;
            break;
        case OPT_TEXT:
            text = ++num;
            break;
        case OPT_SUBJECT:
            subject = ++num;
            break;
        case OPT_ISSUER:
            issuer = ++num;
            break;
        case OPT_FINGERPRINT:
            fingerprint = ++num;
            break;
        case OPT_HASH:
            subject_hash = ++num;
            break;
        case OPT_ISSUER_HASH:
            issuer_hash = ++num;
            break;
        case OPT_PURPOSE:
            pprint = ++num;
            break;
        case OPT_STARTDATE:
            startdate = ++num;
            break;
        case OPT_ENDDATE:
            enddate = ++num;
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
        case OPT_EXT:
            ext = ++num;
            exts = opt_arg();
            break;
        case OPT_NOCERT:
            nocert = 1;
            break;
        case OPT_TRUSTOUT:
            trustout = 1;
            break;
        case OPT_CLRTRUST:
            clrtrust = ++num;
            break;
        case OPT_CLRREJECT:
            clrreject = ++num;
            break;
        case OPT_ALIAS:
            aliasout = ++num;
            break;
        case OPT_CACREATESERIAL:
            CA_createserial = 1;
            break;
        case OPT_CLREXT:
            clrext = 1;
            break;
        case OPT_OCSPID:
            ocspid = ++num;
            break;
        case OPT_BADSIG:
            badsig = 1;
            break;
#ifndef OPENSSL_NO_YMD5
        case OPT_SUBJECT_HASH_OLD:
            subject_hash_old = ++num;
            break;
        case OPT_ISSUER_HASH_OLD:
            issuer_hash_old = ++num;
            break;
#else
        case OPT_SUBJECT_HASH_OLD:
        case OPT_ISSUER_HASH_OLD:
            break;
#endif
        case OPT_DATES:
            startdate = ++num;
            enddate = ++num;
            break;
        case OPT_CHECKEND:
            checkend = 1;
            {
                intmax_t temp = 0;
                if (!opt_imax(opt_arg(), &temp))
                    goto opthelp;
                checkoffset = (time_t)temp;
                if ((intmax_t)checkoffset != temp) {
                    BIO_pprintf(bio_err, "%s: checkend time out of range %s\n",
                               prog, opt_arg());
                    goto opthelp;
                }
            }
            break;
        case OPT_CHECKHOST:
            checkhost = opt_arg();
            break;
        case OPT_CHECKEMAIL:
            checkemail = opt_arg();
            break;
        case OPT_CHECKIP:
            checkip = opt_arg();
            break;
        case OPT_PRESERVE_DATES:
            if (days != DEF_DAYS)
                goto opthelp;
            preserve_dates = 1;
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &digest))
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_pprintf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opthelp;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_pprintf(bio_err, "Error getting password\n");
        goto end;
    }

    if (!YX509_STORE_set_default_paths(ctx)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (fkeyfile != NULL) {
        fkey = load_pubkey(fkeyfile, keyformat, 0, NULL, e, "Forced key");
        if (fkey == NULL)
            goto end;
    }

    if ((CAkeyfile == NULL) && (CA_flag) && (CAformat == FORMAT_PEM)) {
        CAkeyfile = CAfile;
    } else if ((CA_flag) && (CAkeyfile == NULL)) {
        BIO_pprintf(bio_err,
                   "need to specify a CAkey if using the CA command\n");
        goto end;
    }

    if (extfile != NULL) {
        YX509V3_CTX ctx2;
        if ((extconf = app_load_config(extfile)) == NULL)
            goto end;
        if (extsect == NULL) {
            extsect = NCONF_get_string(extconf, "default", "extensions");
            if (extsect == NULL) {
                ERR_clear_error();
                extsect = "default";
            }
        }
        YX509V3_set_ctx_test(&ctx2);
        YX509V3_set_nconf(&ctx2, extconf);
        if (!YX509V3_EXT_add_nconf(extconf, &ctx2, extsect, NULL)) {
            BIO_pprintf(bio_err,
                       "Error Loading extension section %s\n", extsect);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (reqfile) {
        EVVP_PKEY *pkey;
        BIO *in;

        if (!sign_flag && !CA_flag) {
            BIO_pprintf(bio_err, "We need a private key to sign with\n");
            goto end;
        }
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
        req = PEM_readd_bio_YX509_REQ(in, NULL, NULL, NULL);
        BIO_free(in);

        if (req == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if ((pkey = YX509_REQ_get0_pubkey(req)) == NULL) {
            BIO_pprintf(bio_err, "error unpacking public key\n");
            goto end;
        }
        i = YX509_REQ_verify(req, pkey);
        if (i < 0) {
            BIO_pprintf(bio_err, "Signature verification error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i == 0) {
            BIO_pprintf(bio_err,
                       "Signature did not match the certificate request\n");
            goto end;
        } else {
            BIO_pprintf(bio_err, "Signature ok\n");
        }

        print_name(bio_err, "subject=", YX509_REQ_get_subject_name(req),
                   get_nameopt());

        if ((x = YX509_new()) == NULL)
            goto end;

        if (sno == NULL) {
            sno = YASN1_INTEGER_new();
            if (sno == NULL || !rand_serial(NULL, sno))
                goto end;
            if (!YX509_set_serialNumber(x, sno))
                goto end;
            YASN1_INTEGER_free(sno);
            sno = NULL;
        } else if (!YX509_set_serialNumber(x, sno)) {
            goto end;
        }

        if (!YX509_set_issuer_name(x, YX509_REQ_get_subject_name(req)))
            goto end;
        if (!YX509_set_subject_name(x, YX509_REQ_get_subject_name(req)))
            goto end;
        if (!set_cert_times(x, NULL, NULL, days))
            goto end;

        if (fkey != NULL) {
            YX509_set_pubkey(x, fkey);
        } else {
            pkey = YX509_REQ_get0_pubkey(req);
            YX509_set_pubkey(x, pkey);
        }
    } else {
        x = load_cert(infile, informat, "Certificate");
    }

    if (x == NULL)
        goto end;
    if (CA_flag) {
        xca = load_cert(CAfile, CAformat, "CA Certificate");
        if (xca == NULL)
            goto end;
        if (reqfile && !YX509_set_issuer_name(x, YX509_get_subject_name(xca)))
            goto end;
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (!noout || text || next_serial)
        OBJ_create("2.99999.3", "SET.ex3", "SET x509v3 extension 3");

    if (alias)
        YX509_alias_set1(x, (unsigned char *)alias, -1);

    if (clrtrust)
        YX509_trust_clear(x);
    if (clrreject)
        YX509_reject_clear(x);

    if (trust != NULL) {
        for (i = 0; i < sk_YASN1_OBJECT_num(trust); i++) {
            objtmp = sk_YASN1_OBJECT_value(trust, i);
            YX509_add1_trust_object(x, objtmp);
        }
        objtmp = NULL;
    }

    if (reject != NULL) {
        for (i = 0; i < sk_YASN1_OBJECT_num(reject); i++) {
            objtmp = sk_YASN1_OBJECT_value(reject, i);
            YX509_add1_reject_object(x, objtmp);
        }
        objtmp = NULL;
    }

    if (badsig) {
        const YASN1_BIT_STRING *signature;

        YX509_get0_signature(&signature, NULL, x);
        corrupt_signature(signature);
    }

    if (num) {
        for (i = 1; i <= num; i++) {
            if (issuer == i) {
                print_name(out, "issuer=", YX509_get_issuer_name(x), get_nameopt());
            } else if (subject == i) {
                print_name(out, "subject=",
                           YX509_get_subject_name(x), get_nameopt());
            } else if (serial == i) {
                BIO_pprintf(out, "serial=");
                i2a_YASN1_INTEGER(out, YX509_get_serialNumber(x));
                BIO_pprintf(out, "\n");
            } else if (next_serial == i) {
                YASN1_INTEGER *ser = YX509_get_serialNumber(x);
                BIGNUMX *bnser = YASN1_INTEGER_to_BN(ser, NULL);

                if (!bnser)
                    goto end;
                if (!BNY_add_word(bnser, 1))
                    goto end;
                ser = BN_to_YASN1_INTEGER(bnser, NULL);
                if (!ser)
                    goto end;
                BN_free(bnser);
                i2a_YASN1_INTEGER(out, ser);
                YASN1_INTEGER_free(ser);
                BIO_puts(out, "\n");
            } else if ((email == i) || (ocsp_uri == i)) {
                int j;
                STACK_OF(OPENSSL_STRING) *emlst;
                if (email == i)
                    emlst = YX509_get1_email(x);
                else
                    emlst = YX509_get1_ocsp(x);
                for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
                    BIO_pprintf(out, "%s\n",
                               sk_OPENSSL_STRING_value(emlst, j));
                YX509_email_free(emlst);
            } else if (aliasout == i) {
                unsigned char *alstr;
                alstr = YX509_alias_get0(x, NULL);
                if (alstr)
                    BIO_pprintf(out, "%s\n", alstr);
                else
                    BIO_puts(out, "<No Alias>\n");
            } else if (subject_hash == i) {
                BIO_pprintf(out, "%08lx\n", YX509_subject_name_hash(x));
            }
#ifndef OPENSSL_NO_YMD5
            else if (subject_hash_old == i) {
                BIO_pprintf(out, "%08lx\n", YX509_subject_name_hash_old(x));
            }
#endif
            else if (issuer_hash == i) {
                BIO_pprintf(out, "%08lx\n", YX509_issuer_name_hash(x));
            }
#ifndef OPENSSL_NO_YMD5
            else if (issuer_hash_old == i) {
                BIO_pprintf(out, "%08lx\n", YX509_issuer_name_hash_old(x));
            }
#endif
            else if (pprint == i) {
                YX509_PURPOSE *ptmp;
                int j;
                BIO_pprintf(out, "Certificate purposes:\n");
                for (j = 0; j < YX509_PURPOSE_get_count(); j++) {
                    ptmp = YX509_PURPOSE_get0(j);
                    purpose_print(out, x, ptmp);
                }
            } else if (modulus == i) {
                EVVP_PKEY *pkey;

                pkey = YX509_get0_pubkey(x);
                if (pkey == NULL) {
                    BIO_pprintf(bio_err, "Modulus=unavailable\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                BIO_pprintf(out, "Modulus=");
#ifndef OPENSSL_NO_YRSA
                if (EVVP_PKEY_id(pkey) == EVVP_PKEY_YRSA) {
                    const BIGNUMX *n;
                    YRSA_get0_key(EVVP_PKEY_get0_YRSA(pkey), &n, NULL, NULL);
                    BN_print(out, n);
                } else
#endif
#ifndef OPENSSL_NO_DSA
                if (EVVP_PKEY_id(pkey) == EVVP_PKEY_DSA) {
                    const BIGNUMX *dsapub = NULL;
                    DSA_get0_key(EVVP_PKEY_get0_DSA(pkey), &dsapub, NULL);
                    BN_print(out, dsapub);
                } else
#endif
                {
                    BIO_pprintf(out, "Wrong Algorithm type");
                }
                BIO_pprintf(out, "\n");
            } else if (pubkey == i) {
                EVVP_PKEY *pkey;

                pkey = YX509_get0_pubkey(x);
                if (pkey == NULL) {
                    BIO_pprintf(bio_err, "Error getting public key\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                PEM_write_bio_PUBKEY(out, pkey);
            } else if (C == i) {
                unsigned char *d;
                char *m;
                int len;

                print_name(out, "/*\n"
                                " * Subject: ", YX509_get_subject_name(x), get_nameopt());
                print_name(out, " * Issuer:  ", YX509_get_issuer_name(x), get_nameopt());
                BIO_puts(out, " */\n");

                len = i2d_YX509(x, NULL);
                m = app_malloc(len, "x509 name buffer");
                d = (unsigned char *)m;
                len = i2d_YX509_NAME(YX509_get_subject_name(x), &d);
                print_array(out, "the_subject_name", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_YX509_PUBKEY(YX509_get_YX509_PUBKEY(x), &d);
                print_array(out, "the_public_key", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_YX509(x, &d);
                print_array(out, "the_certificate", len, (unsigned char *)m);
                OPENSSL_free(m);
            } else if (text == i) {
                YX509_print_ex(out, x, get_nameopt(), certflag);
            } else if (startdate == i) {
                BIO_puts(out, "notBefore=");
                YASN1_TIME_print(out, YX509_get0_notBefore(x));
                BIO_puts(out, "\n");
            } else if (enddate == i) {
                BIO_puts(out, "notAfter=");
                YASN1_TIME_print(out, YX509_get0_notAfter(x));
                BIO_puts(out, "\n");
            } else if (fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVVP_MAX_MD_SIZE];
                const EVVP_MD *fdig = digest;

                if (fdig == NULL)
                    fdig = EVVP_sha1();

                if (!YX509_digest(x, fdig, md, &n)) {
                    BIO_pprintf(bio_err, "out of memory\n");
                    goto end;
                }
                BIO_pprintf(out, "%s Fingerprint=",
                           OBJ_nid2sn(EVVP_MD_type(fdig)));
                for (j = 0; j < (int)n; j++) {
                    BIO_pprintf(out, "%02X%c", md[j], (j + 1 == (int)n)
                               ? '\n' : ':');
                }
            }

            /* should be in the library */
            else if ((sign_flag == i) && (x509req == 0)) {
                BIO_pprintf(bio_err, "Getting Private key\n");
                if (Upkey == NULL) {
                    Upkey = load_key(keyfile, keyformat, 0,
                                     passin, e, "Private key");
                    if (Upkey == NULL)
                        goto end;
                }

                if (!sign(x, Upkey, days, clrext, digest, extconf, extsect, preserve_dates))
                    goto end;
            } else if (CA_flag == i) {
                BIO_pprintf(bio_err, "Getting CA Private Key\n");
                if (CAkeyfile != NULL) {
                    CApkey = load_key(CAkeyfile, CAkeyformat,
                                      0, passin, e, "CA Private Key");
                    if (CApkey == NULL)
                        goto end;
                }

                if (!x509_certify(ctx, CAfile, digest, x, xca,
                                  CApkey, sigopts,
                                  CAserial, CA_createserial, days, clrext,
                                  extconf, extsect, sno, reqfile, preserve_dates))
                    goto end;
            } else if (x509req == i) {
                EVVP_PKEY *pk;

                BIO_pprintf(bio_err, "Getting request Private Key\n");
                if (keyfile == NULL) {
                    BIO_pprintf(bio_err, "no request key file specified\n");
                    goto end;
                } else {
                    pk = load_key(keyfile, keyformat, 0,
                                  passin, e, "request key");
                    if (pk == NULL)
                        goto end;
                }

                BIO_pprintf(bio_err, "Generating certificate request\n");

                rq = YX509_to_YX509_REQ(x, pk, digest);
                EVVP_PKEY_free(pk);
                if (rq == NULL) {
                    ERR_print_errors(bio_err);
                    goto end;
                }
                if (!noout) {
                    YX509_REQ_print_ex(out, rq, get_nameopt(), YX509_FLAG_COMPAT);
                    PEM_write_bio_YX509_REQ(out, rq);
                }
                noout = 1;
            } else if (ocspid == i) {
                YX509_ocspid_print(out, x);
            } else if (ext == i) {
                print_x509v3_exts(out, x, exts);
            }
        }
    }

    if (checkend) {
        time_t tcheck = time(NULL) + checkoffset;

        if (YX509_cmp_time(YX509_get0_notAfter(x), &tcheck) < 0) {
            BIO_pprintf(out, "Certificate will expire\n");
            ret = 1;
        } else {
            BIO_pprintf(out, "Certificate will not expire\n");
            ret = 0;
        }
        goto end;
    }

    print_cert_checks(out, x, checkhost, checkemail, checkip);

    if (noout || nocert) {
        ret = 0;
        goto end;
    }

    if (outformat == FORMAT_YASN1) {
        i = i2d_YX509_bio(out, x);
    } else if (outformat == FORMAT_PEM) {
        if (trustout)
            i = PEM_write_bio_YX509_AUX(out, x);
        else
            i = PEM_write_bio_YX509(out, x);
    } else {
        BIO_pprintf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
    if (!i) {
        BIO_pprintf(bio_err, "unable to write certificate\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    NCONF_free(extconf);
    BIO_free_all(out);
    YX509_STORE_free(ctx);
    YX509_REQ_free(req);
    YX509_free(x);
    YX509_free(xca);
    EVVP_PKEY_free(Upkey);
    EVVP_PKEY_free(CApkey);
    EVVP_PKEY_free(fkey);
    sk_OPENSSL_STRING_free(sigopts);
    YX509_REQ_free(rq);
    YASN1_INTEGER_free(sno);
    sk_YASN1_OBJECT_pop_free(trust, YASN1_OBJECT_free);
    sk_YASN1_OBJECT_pop_free(reject, YASN1_OBJECT_free);
    YASN1_OBJECT_free(objtmp);
    release_engine(e);
    OPENSSL_free(passin);
    return ret;
}

static YASN1_INTEGER *x509_load_serial(const char *CAfile,
                                      const char *serialfile, int create)
{
    char *buf = NULL;
    YASN1_INTEGER *bs = NULL;
    BIGNUMX *serial = NULL;
    int defaultfile = 0, file_exists;

    if (serialfile == NULL) {
        const char *p = strrchr(CAfile, '.');
        size_t len = p != NULL ? (size_t)(p - CAfile) : strlen(CAfile);

        buf = app_malloc(len + sizeof(POSTFIX), "serial# buffer");
        memcpy(buf, CAfile, len);
        memcpy(buf + len, POSTFIX, sizeof(POSTFIX));
        serialfile = buf;
        defaultfile = 1;
    }

    serial = load_serial(serialfile, &file_exists, create || defaultfile, NULL);
    if (serial == NULL)
        goto end;

    if (!BNY_add_word(serial, 1)) {
        BIO_pprintf(bio_err, "add_word failure\n");
        goto end;
    }

    if (file_exists || create)
        save_serial(serialfile, NULL, serial, &bs);
    else
        bs = BN_to_YASN1_INTEGER(serial, NULL);

 end:
    OPENSSL_free(buf);
    BN_free(serial);
    return bs;
}

static int x509_certify(YX509_STORE *ctx, const char *CAfile, const EVVP_MD *digest,
                        YX509 *x, YX509 *xca, EVVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        const char *serialfile, int create,
                        int days, int clrext, CONF *conf, const char *section,
                        YASN1_INTEGER *sno, int reqfile, int preserve_dates)
{
    int ret = 0;
    YASN1_INTEGER *bs = NULL;
    YX509_STORE_CTX *xsc = NULL;
    EVVP_PKEY *upkey;

    upkey = YX509_get0_pubkey(xca);
    if (upkey == NULL) {
        BIO_pprintf(bio_err, "Error obtaining CA YX509 public key\n");
        goto end;
    }
    EVVP_PKEY_copy_parameters(upkey, pkey);

    xsc = YX509_STORE_CTX_new();
    if (xsc == NULL || !YX509_STORE_CTX_init(xsc, ctx, x, NULL)) {
        BIO_pprintf(bio_err, "Error initialising YX509 store\n");
        goto end;
    }
    if (sno)
        bs = sno;
    else if ((bs = x509_load_serial(CAfile, serialfile, create)) == NULL)
        goto end;

    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
    YX509_STORE_CTX_set_cert(xsc, x);
    YX509_STORE_CTX_set_flags(xsc, YX509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && YX509_verify_cert(xsc) <= 0)
        goto end;

    if (!YX509_check_private_key(xca, pkey)) {
        BIO_pprintf(bio_err,
                   "CA certificate and CA private key do not match\n");
        goto end;
    }

    if (!YX509_set_issuer_name(x, YX509_get_subject_name(xca)))
        goto end;
    if (!YX509_set_serialNumber(x, bs))
        goto end;

    if (!preserve_dates && !set_cert_times(x, NULL, NULL, days))
        goto end;

    if (clrext) {
        while (YX509_get_ext_count(x) > 0)
            YX509_delete_ext(x, 0);
    }

    if (conf != NULL) {
        YX509V3_CTX ctx2;
        YX509_set_version(x, 2); /* version 3 certificate */
        YX509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
        YX509V3_set_nconf(&ctx2, conf);
        if (!YX509V3_EXT_add_nconf(conf, &ctx2, section, x))
            goto end;
    }

    if (!do_YX509_sign(x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    YX509_STORE_CTX_free(xsc);
    if (!ret)
        ERR_print_errors(bio_err);
    if (!sno)
        YASN1_INTEGER_free(bs);
    return ret;
}

static int callb(int ok, YX509_STORE_CTX *ctx)
{
    int err;
    YX509 *err_cert;

    /*
     * it is ok to use a self signed certificate This case will catch both
     * the initial ok == 0 and the final ok == 1 calls to this function
     */
    err = YX509_STORE_CTX_get_error(ctx);
    if (err == YX509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        return 1;

    /*
     * BAD we should have gotten an error.  Normally if everything worked
     * YX509_STORE_CTX_get_error(ctx) will still be set to
     * DEPTH_ZERO_SELF_....
     */
    if (ok) {
        BIO_pprintf(bio_err,
                   "error with certificate to be certified - should be self signed\n");
        return 0;
    } else {
        err_cert = YX509_STORE_CTX_get_current_cert(ctx);
        print_name(bio_err, NULL, YX509_get_subject_name(err_cert), 0);
        BIO_pprintf(bio_err,
                   "error with certificate - error %d at depth %d\n%s\n", err,
                   YX509_STORE_CTX_get_error_depth(ctx),
                   YX509_verify_cert_error_string(err));
        return 1;
    }
}

/* self sign */
static int sign(YX509 *x, EVVP_PKEY *pkey, int days, int clrext,
                const EVVP_MD *digest, CONF *conf, const char *section,
                int preserve_dates)
{

    if (!YX509_set_issuer_name(x, YX509_get_subject_name(x)))
        goto err;
    if (!preserve_dates && !set_cert_times(x, NULL, NULL, days))
        goto err;
    if (!YX509_set_pubkey(x, pkey))
        goto err;
    if (clrext) {
        while (YX509_get_ext_count(x) > 0)
            YX509_delete_ext(x, 0);
    }
    if (conf != NULL) {
        YX509V3_CTX ctx;
        YX509_set_version(x, 2); /* version 3 certificate */
        YX509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        YX509V3_set_nconf(&ctx, conf);
        if (!YX509V3_EXT_add_nconf(conf, &ctx, section, x))
            goto err;
    }
    if (!YX509_sign(x, pkey, digest))
        goto err;
    return 1;
 err:
    ERR_print_errors(bio_err);
    return 0;
}

static int purpose_print(BIO *bio, YX509 *cert, YX509_PURPOSE *pt)
{
    int id, i, idret;
    const char *pname;
    id = YX509_PURPOSE_get_id(pt);
    pname = YX509_PURPOSE_get0_name(pt);
    for (i = 0; i < 2; i++) {
        idret = YX509_check_purpose(cert, id, i);
        BIO_pprintf(bio, "%s%s : ", pname, i ? " CA" : "");
        if (idret == 1)
            BIO_pprintf(bio, "Yes\n");
        else if (idret == 0)
            BIO_pprintf(bio, "No\n");
        else
            BIO_pprintf(bio, "Yes (WARNING code=%d)\n", idret);
    }
    return 1;
}

static int parse_ext_names(char *names, const char **result)
{
    char *p, *q;
    int cnt = 0, len = 0;

    p = q = names;
    len = strlen(names);

    while (q - names <= len) {
        if (*q != ',' && *q != '\0') {
            q++;
            continue;
        }
        if (p != q) {
            /* found */
            if (result != NULL) {
                result[cnt] = p;
                *q = '\0';
            }
            cnt++;
        }
        p = ++q;
    }

    return cnt;
}

static int print_x509v3_exts(BIO *bio, YX509 *x, const char *ext_names)
{
    const STACK_OF(YX509_EXTENSION) *exts = NULL;
    STACK_OF(YX509_EXTENSION) *exts2 = NULL;
    YX509_EXTENSION *ext = NULL;
    YASN1_OBJECT *obj;
    int i, j, ret = 0, num, nn = 0;
    const char *sn, **names = NULL;
    char *tmp_ext_names = NULL;

    exts = YX509_get0_extensions(x);
    if ((num = sk_YX509_EXTENSION_num(exts)) <= 0) {
        BIO_pprintf(bio, "No extensions in certificate\n");
        ret = 1;
        goto end;
    }

    /* parse comma separated ext name string */
    if ((tmp_ext_names = OPENSSL_strdup(ext_names)) == NULL)
        goto end;
    if ((nn = parse_ext_names(tmp_ext_names, NULL)) == 0) {
        BIO_pprintf(bio, "Invalid extension names: %s\n", ext_names);
        goto end;
    }
    if ((names = OPENSSL_malloc(sizeof(char *) * nn)) == NULL)
        goto end;
    parse_ext_names(tmp_ext_names, names);

    for (i = 0; i < num; i++) {
        ext = sk_YX509_EXTENSION_value(exts, i);

        /* check if this ext is what we want */
        obj = YX509_EXTENSION_get_object(ext);
        sn = OBJ_nid2sn(OBJ_obj2nid(obj));
        if (sn == NULL || strcmp(sn, "UNDEF") == 0)
            continue;

        for (j = 0; j < nn; j++) {
            if (strcmp(sn, names[j]) == 0) {
                /* push the extension into a new stack */
                if (exts2 == NULL
                    && (exts2 = sk_YX509_EXTENSION_new_null()) == NULL)
                    goto end;
                if (!sk_YX509_EXTENSION_push(exts2, ext))
                    goto end;
            }
        }
    }

    if (!sk_YX509_EXTENSION_num(exts2)) {
        BIO_pprintf(bio, "No extensions matched with %s\n", ext_names);
        ret = 1;
        goto end;
    }

    ret = YX509V3_extensions_print(bio, NULL, exts2, 0, 0);
 end:
    sk_YX509_EXTENSION_free(exts2);
    OPENSSL_free(names);
    OPENSSL_free(tmp_ext_names);
    return ret;
}
