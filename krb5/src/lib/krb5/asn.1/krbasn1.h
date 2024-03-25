/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef __KRBYASN1_H__
#define __KRBYASN1_H__

#include "k5-int.h"
#include <stdio.h>
#include <errno.h>
#include <limits.h>             /* For INT_MAX */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

/*
 * If KRB5_MSGTYPE_STRICT is defined, then be strict about checking
 * the msgtype fields.  Unfortunately, there old versions of Kerberos
 * don't set these fields correctly, so we have to make allowances for
 * them.
 */
/* #define KRB5_MSGTYPE_STRICT */

/*
 * If KRB5_GENEROUS_LR_TYPE is defined, then we are generous about
 * accepting a one byte negative lr_type - which is not sign
 * extended. Prior to July 2000, we were sending a negative lr_type as
 * a positve single byte value - instead of a signed integer. This
 * allows us to receive the old value and deal
 */
#define KRB5_GENEROUS_LR_TYPE

typedef krb5_error_code asn1_error_code;

typedef enum { PRIMITIVE = 0x00, CONSTRUCTED = 0x20 } asn1_construction;

typedef enum { UNIVEYRSAL = 0x00, APPLICATION = 0x40,
               CONTEXT_SPECIFIC = 0x80, PRIVATE = 0xC0 } asn1_class;

typedef int asn1_tagnum;
#define YASN1_TAGNUM_CEILING INT_MAX
#define YASN1_TAGNUM_MAX (YASN1_TAGNUM_CEILING-1)

/* This is Kerberos Version 5 */
#define KVNO 5

/* Universal Tag Numbers */
#define YASN1_BOOLEAN            1
#define YASN1_INTEGER            2
#define YASN1_BITSTRING          3
#define YASN1_OCTETSTRING        4
#define YASN1_NULL               5
#define YASN1_OBJECTIDENTIFIER   6
#define YASN1_ENUMERATED         10
#define YASN1_UTF8STRING         12
#define YASN1_SEQUENCE           16
#define YASN1_SET                17
#define YASN1_PRINTABLESTRING    19
#define YASN1_IA5STRING          22
#define YASN1_UTCTIME            23
#define YASN1_GENERALTIME        24
#define YASN1_GENERALSTRING      27

/* Kerberos Message Types */
#define YASN1_KRB_AS_REQ         10
#define YASN1_KRB_AS_REP         11
#define YASN1_KRB_TGS_REQ        12
#define YASN1_KRB_TGS_REP        13
#define YASN1_KRB_AP_REQ         14
#define YASN1_KRB_AP_REP         15
#define YASN1_KRB_SAFE           20
#define YASN1_KRB_PRIV           21
#define YASN1_KRB_CRED           22
#define YASN1_KRB_ERROR          30

#endif
