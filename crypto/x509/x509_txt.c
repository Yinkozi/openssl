/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/objects.h>

const char *YX509_verify_cert_error_string(long n)
{
    switch ((int)n) {
    case YX509_V_OK:
        return "ok";
    case YX509_V_ERR_UNSPECIFIED:
        return "unspecified certificate verification error";
    case YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        return "unable to get issuer certificate";
    case YX509_V_ERR_UNABLE_TO_GET_CRL:
        return "unable to get certificate CRL";
    case YX509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        return "unable to decrypt certificate's signature";
    case YX509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        return "unable to decrypt CRL's signature";
    case YX509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        return "unable to decode issuer public key";
    case YX509_V_ERR_CERT_SIGNATURE_FAILURE:
        return "certificate signature failure";
    case YX509_V_ERR_CRL_SIGNATURE_FAILURE:
        return "CRL signature failure";
    case YX509_V_ERR_CERT_NOT_YET_VALID:
        return "certificate is not yet valid";
    case YX509_V_ERR_CERT_HAS_EXPIRED:
        return "certificate has expired";
    case YX509_V_ERR_CRL_NOT_YET_VALID:
        return "CRL is not yet valid";
    case YX509_V_ERR_CRL_HAS_EXPIRED:
        return "CRL has expired";
    case YX509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return "format error in certificate's notBefore field";
    case YX509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return "format error in certificate's notAfter field";
    case YX509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        return "format error in CRL's lastUpdate field";
    case YX509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        return "format error in CRL's nextUpdate field";
    case YX509_V_ERR_OUT_OF_MEM:
        return "out of memory";
    case YX509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return "self signed certificate";
    case YX509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        return "self signed certificate in certificate chain";
    case YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "unable to get local issuer certificate";
    case YX509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return "unable to verify the first certificate";
    case YX509_V_ERR_CERT_CHAIN_TOO_LONG:
        return "certificate chain too long";
    case YX509_V_ERR_CERT_REVOKED:
        return "certificate revoked";
    case YX509_V_ERR_INVALID_CA:
        return "invalid CA certificate";
    case YX509_V_ERR_PATH_LENGTH_EXCEEDED:
        return "path length constraint exceeded";
    case YX509_V_ERR_INVALID_PURPOSE:
        return "unsupported certificate purpose";
    case YX509_V_ERR_CERT_UNTRUSTED:
        return "certificate not trusted";
    case YX509_V_ERR_CERT_REJECTED:
        return "certificate rejected";
    case YX509_V_ERR_SUBJECT_ISSUER_MISMATCH:
        return "subject issuer mismatch";
    case YX509_V_ERR_AKID_SKID_MISMATCH:
        return "authority and subject key identifier mismatch";
    case YX509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
        return "authority and issuer serial number mismatch";
    case YX509_V_ERR_KEYUSAGE_NO_CERTSIGN:
        return "key usage does not include certificate signing";
    case YX509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        return "unable to get CRL issuer certificate";
    case YX509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        return "unhandled critical extension";
    case YX509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
        return "key usage does not include CRL signing";
    case YX509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
        return "unhandled critical CRL extension";
    case YX509_V_ERR_INVALID_NON_CA:
        return "invalid non-CA certificate (has CA markings)";
    case YX509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
        return "proxy path length constraint exceeded";
    case YX509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
        return "key usage does not include digital signature";
    case YX509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
        return
            "proxy certificates not allowed, please set the appropriate flag";
    case YX509_V_ERR_INVALID_EXTENSION:
        return "invalid or inconsistent certificate extension";
    case YX509_V_ERR_INVALID_POLICY_EXTENSION:
        return "invalid or inconsistent certificate policy extension";
    case YX509_V_ERR_NO_EXPLICIT_POLICY:
        return "no explicit policy";
    case YX509_V_ERR_DIFFERENT_CRL_SCOPE:
        return "Different CRL scope";
    case YX509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
        return "Unsupported extension feature";
    case YX509_V_ERR_UNNESTED_RESOURCE:
        return "RFC 3779 resource not subset of parent's resources";
    case YX509_V_ERR_PERMITTED_VIOLATION:
        return "permitted subtree violation";
    case YX509_V_ERR_EXCLUDED_VIOLATION:
        return "excluded subtree violation";
    case YX509_V_ERR_SUBTREE_MINMAX:
        return "name constraints minimum and maximum not supported";
    case YX509_V_ERR_APPLICATION_VERIFICATION:
        return "application verification failure";
    case YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
        return "unsupported name constraint type";
    case YX509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
        return "unsupported or invalid name constraint syntax";
    case YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
        return "unsupported or invalid name syntax";
    case YX509_V_ERR_CRL_PATH_VALIDATION_ERROR:
        return "CRL path validation error";
    case YX509_V_ERR_PATH_LOOP:
        return "Path Loop";
    case YX509_V_ERR_SUITE_B_INVALID_VERSION:
        return "Suite B: certificate version invalid";
    case YX509_V_ERR_SUITE_B_INVALID_ALGORITHM:
        return "Suite B: invalid public key algorithm";
    case YX509_V_ERR_SUITE_B_INVALID_CURVE:
        return "Suite B: invalid ECC curve";
    case YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
        return "Suite B: invalid signature algorithm";
    case YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
        return "Suite B: curve not allowed for this LOS";
    case YX509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
        return "Suite B: cannot sign P-384 with P-256";
    case YX509_V_ERR_HOSTNAME_MISMATCH:
        return "Hostname mismatch";
    case YX509_V_ERR_EMAIL_MISMATCH:
        return "Email address mismatch";
    case YX509_V_ERR_IP_ADDRESS_MISMATCH:
        return "IP address mismatch";
    case YX509_V_ERR_DANE_NO_MATCH:
        return "No matching DANE TLSA records";
    case YX509_V_ERR_EE_KEY_TOO_SMALL:
        return "EE certificate key too weak";
    case YX509_V_ERR_CA_KEY_TOO_SMALL:
        return "CA certificate key too weak";
    case YX509_V_ERR_CA_MD_TOO_WEAK:
        return "CA signature digest algorithm too weak";
    case YX509_V_ERR_INVALID_CALL:
        return "Invalid certificate verification context";
    case YX509_V_ERR_STORE_LOOKUP:
        return "Issuer certificate lookup error";
    case YX509_V_ERR_NO_VALID_SCTS:
        return "Certificate Transparency required, but no valid SCTs found";
    case YX509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
        return "proxy subject name violation";
    case YX509_V_ERR_OCSP_VERIFY_NEEDED:
        return "OCSP verification needed";
    case YX509_V_ERR_OCSP_VERIFY_FAILED:
        return "OCSP verification failed";
    case YX509_V_ERR_OCSP_CERT_UNKNOWN:
        return "OCSP unknown cert";
    case YX509_V_ERR_EC_KEY_EXPLICIT_PARAMS:
        return "Certificate public key has explicit ECC parameters";

    default:
        /* Printing an error number into a static buffer is not thread-safe */
        return "unknown certificate verification error";
    }
}
