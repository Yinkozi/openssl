/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YASN1T_H
# define HEADER_YASN1T_H

# include <stddef.h>
# include <openssl/e_os2.h>
# include <openssl/asn1.h>

# ifdef OPENSSL_BUILD_SHLIBCRYPTO
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

/* YASN1 template defines, structures and functions */

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

/* Macro to obtain YASN1_ADB pointer from a type (only used internally) */
#  define YASN1_ADB_ptr(iptr) ((const YASN1_ADB *)(iptr))

/* Macros for start and end of YASN1_ITEM definition */

#  define YASN1_ITEM_start(itname) \
        const YASN1_ITEM itname##_it = {

#  define static_YASN1_ITEM_start(itname) \
        static const YASN1_ITEM itname##_it = {

#  define YASN1_ITEM_end(itname)                 \
                };

# else

/* Macro to obtain YASN1_ADB pointer from a type (only used internally) */
#  define YASN1_ADB_ptr(iptr) ((const YASN1_ADB *)((iptr)()))

/* Macros for start and end of YASN1_ITEM definition */

#  define YASN1_ITEM_start(itname) \
        const YASN1_ITEM * itname##_it(void) \
        { \
                static const YASN1_ITEM local_it = {

#  define static_YASN1_ITEM_start(itname) \
        static YASN1_ITEM_start(itname)

#  define YASN1_ITEM_end(itname) \
                }; \
        return &local_it; \
        }

# endif

/* Macros to aid YASN1 template writing */

# define YASN1_ITEM_TEMPLATE(tname) \
        static const YASN1_TEMPLATE tname##_item_tt

# define YASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        YASN1_ITEM_end(tname)
# define static_YASN1_ITEM_TEMPLATE_END(tname) \
        ;\
        static_YASN1_ITEM_start(tname) \
                YASN1_ITYPE_PRIMITIVE,\
                -1,\
                &tname##_item_tt,\
                0,\
                NULL,\
                0,\
                #tname \
        YASN1_ITEM_end(tname)

/* This is a YASN1 type which just embeds a template */

/*-
 * This pair helps declare a SEQUENCE. We can do:
 *
 *      YASN1_SEQUENCE(stname) = {
 *              ... SEQUENCE components ...
 *      } YASN1_SEQUENCE_END(stname)
 *
 *      This will produce an YASN1_ITEM called stname_it
 *      for a structure called stname.
 *
 *      If you want the same structure but a different
 *      name then use:
 *
 *      YASN1_SEQUENCE(itname) = {
 *              ... SEQUENCE components ...
 *      } YASN1_SEQUENCE_END_name(stname, itname)
 *
 *      This will create an item called itname_it using
 *      a structure called stname.
 */

# define YASN1_SEQUENCE(tname) \
        static const YASN1_TEMPLATE tname##_seq_tt[]

# define YASN1_SEQUENCE_END(stname) YASN1_SEQUENCE_END_name(stname, stname)

# define static_YASN1_SEQUENCE_END(stname) static_YASN1_SEQUENCE_END_name(stname, stname)

# define YASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #tname \
        YASN1_ITEM_end(tname)

# define static_YASN1_SEQUENCE_END_name(stname, tname) \
        ;\
        static_YASN1_ITEM_start(tname) \
                YASN1_ITYPE_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

# define YASN1_NDEF_SEQUENCE(tname) \
        YASN1_SEQUENCE(tname)

# define YASN1_NDEF_SEQUENCE_cb(tname, cb) \
        YASN1_SEQUENCE_cb(tname, cb)

# define YASN1_SEQUENCE_cb(tname, cb) \
        static const YASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        YASN1_SEQUENCE(tname)

# define YASN1_BROKEN_SEQUENCE(tname) \
        static const YASN1_AUX tname##_aux = {NULL, YASN1_AFLG_BROKEN, 0, 0, 0, 0}; \
        YASN1_SEQUENCE(tname)

# define YASN1_SEQUENCE_ref(tname, cb) \
        static const YASN1_AUX tname##_aux = {NULL, YASN1_AFLG_REFCOUNT, offsetof(tname, references), offsetof(tname, lock), cb, 0}; \
        YASN1_SEQUENCE(tname)

# define YASN1_SEQUENCE_enc(tname, enc, cb) \
        static const YASN1_AUX tname##_aux = {NULL, YASN1_AFLG_ENCODING, 0, 0, cb, offsetof(tname, enc)}; \
        YASN1_SEQUENCE(tname)

# define YASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_NDEF_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        YASN1_ITEM_end(tname)
# define static_YASN1_NDEF_SEQUENCE_END(tname) \
        ;\
        static_YASN1_ITEM_start(tname) \
                YASN1_ITYPE_NDEF_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(tname),\
                #tname \
        YASN1_ITEM_end(tname)

# define YASN1_BROKEN_SEQUENCE_END(stname) YASN1_SEQUENCE_END_ref(stname, stname)
# define static_YASN1_BROKEN_SEQUENCE_END(stname) \
        static_YASN1_SEQUENCE_END_ref(stname, stname)

# define YASN1_SEQUENCE_END_enc(stname, tname) YASN1_SEQUENCE_END_ref(stname, tname)

# define YASN1_SEQUENCE_END_cb(stname, tname) YASN1_SEQUENCE_END_ref(stname, tname)
# define static_YASN1_SEQUENCE_END_cb(stname, tname) static_YASN1_SEQUENCE_END_ref(stname, tname)

# define YASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #tname \
        YASN1_ITEM_end(tname)
# define static_YASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        static_YASN1_ITEM_start(tname) \
                YASN1_ITYPE_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

# define YASN1_NDEF_SEQUENCE_END_cb(stname, tname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_NDEF_SEQUENCE,\
                V_YASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(YASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

/*-
 * This pair helps declare a CHOICE type. We can do:
 *
 *      YASN1_CHOICE(chname) = {
 *              ... CHOICE options ...
 *      YASN1_CHOICE_END(chname)
 *
 *      This will produce an YASN1_ITEM called chname_it
 *      for a structure called chname. The structure
 *      definition must look like this:
 *      typedef struct {
 *              int type;
 *              union {
 *                      YASN1_SOMETHING *opt1;
 *                      YASN1_SOMEOTHER *opt2;
 *              } value;
 *      } chname;
 *
 *      the name of the selector must be 'type'.
 *      to use an alternative selector name use the
 *      YASN1_CHOICE_END_selector() version.
 */

# define YASN1_CHOICE(tname) \
        static const YASN1_TEMPLATE tname##_ch_tt[]

# define YASN1_CHOICE_cb(tname, cb) \
        static const YASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        YASN1_CHOICE(tname)

# define YASN1_CHOICE_END(stname) YASN1_CHOICE_END_name(stname, stname)

# define static_YASN1_CHOICE_END(stname) static_YASN1_CHOICE_END_name(stname, stname)

# define YASN1_CHOICE_END_name(stname, tname) YASN1_CHOICE_END_selector(stname, tname, type)

# define static_YASN1_CHOICE_END_name(stname, tname) static_YASN1_CHOICE_END_selector(stname, tname, type)

# define YASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

# define static_YASN1_CHOICE_END_selector(stname, tname, selname) \
        ;\
        static_YASN1_ITEM_start(tname) \
                YASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(YASN1_TEMPLATE),\
                NULL,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

# define YASN1_CHOICE_END_cb(stname, tname, selname) \
        ;\
        YASN1_ITEM_start(tname) \
                YASN1_ITYPE_CHOICE,\
                offsetof(stname,selname) ,\
                tname##_ch_tt,\
                sizeof(tname##_ch_tt) / sizeof(YASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        YASN1_ITEM_end(tname)

/* This helps with the template wrapper form of YASN1_ITEM */

# define YASN1_EX_TEMPLATE_TYPE(flags, tag, name, type) { \
        (flags), (tag), 0,\
        #name, YASN1_ITEM_ref(type) }

/* These help with SEQUENCE or CHOICE components */

/* used to declare other types */

# define YASN1_EX_TYPE(flags, tag, stname, field, type) { \
        (flags), (tag), offsetof(stname, field),\
        #field, YASN1_ITEM_ref(type) }

/* implicit and explicit helper macros */

# define YASN1_IMP_EX(stname, field, type, tag, ex) \
         YASN1_EX_TYPE(YASN1_TFLG_IMPLICIT | (ex), tag, stname, field, type)

# define YASN1_EXP_EX(stname, field, type, tag, ex) \
         YASN1_EX_TYPE(YASN1_TFLG_EXPLICIT | (ex), tag, stname, field, type)

/* Any defined by macros: the field used is in the table itself */

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION
#  define YASN1_ADB_OBJECT(tblname) { YASN1_TFLG_ADB_OID, -1, 0, #tblname, (const YASN1_ITEM *)&(tblname##_adb) }
#  define YASN1_ADB_INTEGER(tblname) { YASN1_TFLG_ADB_INT, -1, 0, #tblname, (const YASN1_ITEM *)&(tblname##_adb) }
# else
#  define YASN1_ADB_OBJECT(tblname) { YASN1_TFLG_ADB_OID, -1, 0, #tblname, tblname##_adb }
#  define YASN1_ADB_INTEGER(tblname) { YASN1_TFLG_ADB_INT, -1, 0, #tblname, tblname##_adb }
# endif
/* Plain simple type */
# define YASN1_SIMPLE(stname, field, type) YASN1_EX_TYPE(0,0, stname, field, type)
/* Embedded simple type */
# define YASN1_EMBED(stname, field, type) YASN1_EX_TYPE(YASN1_TFLG_EMBED,0, stname, field, type)

/* OPTIONAL simple type */
# define YASN1_OPT(stname, field, type) YASN1_EX_TYPE(YASN1_TFLG_OPTIONAL, 0, stname, field, type)
# define YASN1_OPT_EMBED(stname, field, type) YASN1_EX_TYPE(YASN1_TFLG_OPTIONAL|YASN1_TFLG_EMBED, 0, stname, field, type)

/* IMPLICIT tagged simple type */
# define YASN1_IMP(stname, field, type, tag) YASN1_IMP_EX(stname, field, type, tag, 0)
# define YASN1_IMP_EMBED(stname, field, type, tag) YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_EMBED)

/* IMPLICIT tagged OPTIONAL simple type */
# define YASN1_IMP_OPT(stname, field, type, tag) YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_OPTIONAL)
# define YASN1_IMP_OPT_EMBED(stname, field, type, tag) YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_OPTIONAL|YASN1_TFLG_EMBED)

/* Same as above but EXPLICIT */

# define YASN1_EXP(stname, field, type, tag) YASN1_EXP_EX(stname, field, type, tag, 0)
# define YASN1_EXP_EMBED(stname, field, type, tag) YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_EMBED)
# define YASN1_EXP_OPT(stname, field, type, tag) YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_OPTIONAL)
# define YASN1_EXP_OPT_EMBED(stname, field, type, tag) YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_OPTIONAL|YASN1_TFLG_EMBED)

/* SEQUENCE OF type */
# define YASN1_SEQUENCE_OF(stname, field, type) \
                YASN1_EX_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, stname, field, type)

/* OPTIONAL SEQUENCE OF */
# define YASN1_SEQUENCE_OF_OPT(stname, field, type) \
                YASN1_EX_TYPE(YASN1_TFLG_SEQUENCE_OF|YASN1_TFLG_OPTIONAL, 0, stname, field, type)

/* Same as above but for SET OF */

# define YASN1_SET_OF(stname, field, type) \
                YASN1_EX_TYPE(YASN1_TFLG_SET_OF, 0, stname, field, type)

# define YASN1_SET_OF_OPT(stname, field, type) \
                YASN1_EX_TYPE(YASN1_TFLG_SET_OF|YASN1_TFLG_OPTIONAL, 0, stname, field, type)

/* Finally compound types of SEQUENCE, SET, IMPLICIT, EXPLICIT and OPTIONAL */

# define YASN1_IMP_SET_OF(stname, field, type, tag) \
                        YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_SET_OF)

# define YASN1_EXP_SET_OF(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_SET_OF)

# define YASN1_IMP_SET_OF_OPT(stname, field, type, tag) \
                        YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_SET_OF|YASN1_TFLG_OPTIONAL)

# define YASN1_EXP_SET_OF_OPT(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_SET_OF|YASN1_TFLG_OPTIONAL)

# define YASN1_IMP_SEQUENCE_OF(stname, field, type, tag) \
                        YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_SEQUENCE_OF)

# define YASN1_IMP_SEQUENCE_OF_OPT(stname, field, type, tag) \
                        YASN1_IMP_EX(stname, field, type, tag, YASN1_TFLG_SEQUENCE_OF|YASN1_TFLG_OPTIONAL)

# define YASN1_EXP_SEQUENCE_OF(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_SEQUENCE_OF)

# define YASN1_EXP_SEQUENCE_OF_OPT(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_SEQUENCE_OF|YASN1_TFLG_OPTIONAL)

/* EXPLICIT using indefinite length constructed form */
# define YASN1_NDEF_EXP(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_NDEF)

/* EXPLICIT OPTIONAL using indefinite length constructed form */
# define YASN1_NDEF_EXP_OPT(stname, field, type, tag) \
                        YASN1_EXP_EX(stname, field, type, tag, YASN1_TFLG_OPTIONAL|YASN1_TFLG_NDEF)

/* Macros for the YASN1_ADB structure */

# define YASN1_ADB(name) \
        static const YASN1_ADB_TABLE name##_adbtbl[]

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

#  define YASN1_ADB_END(name, flags, field, adb_cb, def, none) \
        ;\
        static const YASN1_ADB name##_adb = {\
                flags,\
                offsetof(name, field),\
                adb_cb,\
                name##_adbtbl,\
                sizeof(name##_adbtbl) / sizeof(YASN1_ADB_TABLE),\
                def,\
                none\
        }

# else

#  define YASN1_ADB_END(name, flags, field, adb_cb, def, none) \
        ;\
        static const YASN1_ITEM *name##_adb(void) \
        { \
        static const YASN1_ADB internal_adb = \
                {\
                flags,\
                offsetof(name, field),\
                adb_cb,\
                name##_adbtbl,\
                sizeof(name##_adbtbl) / sizeof(YASN1_ADB_TABLE),\
                def,\
                none\
                }; \
                return (const YASN1_ITEM *) &internal_adb; \
        } \
        void dummy_function(void)

# endif

# define ADB_ENTRY(val, template) {val, template}

# define YASN1_ADB_TEMPLATE(name) \
        static const YASN1_TEMPLATE name##_tt

/*
 * This is the YASN1 template structure that defines a wrapper round the
 * actual type. It determines the actual position of the field in the value
 * structure, various flags such as OPTIONAL and the field name.
 */

struct YASN1_TEMPLATE_st {
    unsigned long flags;        /* Various flags */
    long tag;                   /* tag, not used if no tagging */
    unsigned long offset;       /* Offset of this field in structure */
    const char *field_name;     /* Field name */
    YASN1_ITEM_EXP *item;        /* Relevant YASN1_ITEM or YASN1_ADB */
};

/* Macro to extract YASN1_ITEM and YASN1_ADB pointer from YASN1_TEMPLATE */

# define YASN1_TEMPLATE_item(t) (t->item_ptr)
# define YASN1_TEMPLATE_adb(t) (t->item_ptr)

typedef struct YASN1_ADB_TABLE_st YASN1_ADB_TABLE;
typedef struct YASN1_ADB_st YASN1_ADB;

struct YASN1_ADB_st {
    unsigned long flags;        /* Various flags */
    unsigned long offset;       /* Offset of selector field */
    int (*adb_cb)(long *psel);  /* Application callback */
    const YASN1_ADB_TABLE *tbl;  /* Table of possible types */
    long tblcount;              /* Number of entries in tbl */
    const YASN1_TEMPLATE *default_tt; /* Type to use if no match */
    const YASN1_TEMPLATE *null_tt; /* Type to use if selector is NULL */
};

struct YASN1_ADB_TABLE_st {
    long value;                 /* NID for an object or value for an int */
    const YASN1_TEMPLATE tt;     /* item for this value */
};

/* template flags */

/* Field is optional */
# define YASN1_TFLG_OPTIONAL      (0x1)

/* Field is a SET OF */
# define YASN1_TFLG_SET_OF        (0x1 << 1)

/* Field is a SEQUENCE OF */
# define YASN1_TFLG_SEQUENCE_OF   (0x2 << 1)

/*
 * Special case: this refers to a SET OF that will be sorted into DER order
 * when encoded *and* the corresponding STACK will be modified to match the
 * new order.
 */
# define YASN1_TFLG_SET_ORDER     (0x3 << 1)

/* Mask for SET OF or SEQUENCE OF */
# define YASN1_TFLG_SK_MASK       (0x3 << 1)

/*
 * These flags mean the tag should be taken from the tag field. If EXPLICIT
 * then the underlying type is used for the inner tag.
 */

/* IMPLICIT tagging */
# define YASN1_TFLG_IMPTAG        (0x1 << 3)

/* EXPLICIT tagging, inner tag from underlying type */
# define YASN1_TFLG_EXPTAG        (0x2 << 3)

# define YASN1_TFLG_TAG_MASK      (0x3 << 3)

/* context specific IMPLICIT */
# define YASN1_TFLG_IMPLICIT      (YASN1_TFLG_IMPTAG|YASN1_TFLG_CONTEXT)

/* context specific EXPLICIT */
# define YASN1_TFLG_EXPLICIT      (YASN1_TFLG_EXPTAG|YASN1_TFLG_CONTEXT)

/*
 * If tagging is in force these determine the type of tag to use. Otherwise
 * the tag is determined by the underlying type. These values reflect the
 * actual octet format.
 */

/* Universal tag */
# define YASN1_TFLG_UNIVEYRSAL     (0x0<<6)
/* Application tag */
# define YASN1_TFLG_APPLICATION   (0x1<<6)
/* Context specific tag */
# define YASN1_TFLG_CONTEXT       (0x2<<6)
/* Private tag */
# define YASN1_TFLG_PRIVATE       (0x3<<6)

# define YASN1_TFLG_TAG_CLASS     (0x3<<6)

/*
 * These are for ANY DEFINED BY type. In this case the 'item' field points to
 * an YASN1_ADB structure which contains a table of values to decode the
 * relevant type
 */

# define YASN1_TFLG_ADB_MASK      (0x3<<8)

# define YASN1_TFLG_ADB_OID       (0x1<<8)

# define YASN1_TFLG_ADB_INT       (0x1<<9)

/*
 * This flag when present in a SEQUENCE OF, SET OF or EXPLICIT causes
 * indefinite length constructed encoding to be used if required.
 */

# define YASN1_TFLG_NDEF          (0x1<<11)

/* Field is embedded and not a pointer */
# define YASN1_TFLG_EMBED         (0x1 << 12)

/* This is the actual YASN1 item itself */

struct YASN1_ITEM_st {
    char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
                                 * or extern */
    long utype;                 /* underlying type */
    const YASN1_TEMPLATE *templates; /* If SEQUENCE or CHOICE this contains
                                     * the contents */
    long tcount;                /* Number of templates if SEQUENCE or CHOICE */
    const void *funcs;          /* functions that handle this type */
    long size;                  /* Structure size (usually) */
    const char *sname;          /* Structure name */
};

/*-
 * These are values for the itype field and
 * determine how the type is interpreted.
 *
 * For PRIMITIVE types the underlying type
 * determines the behaviour if items is NULL.
 *
 * Otherwise templates must contain a single
 * template and the type is treated in the
 * same way as the type specified in the template.
 *
 * For SEQUENCE types the templates field points
 * to the members, the size field is the
 * structure size.
 *
 * For CHOICE types the templates field points
 * to each possible member (typically a union)
 * and the 'size' field is the offset of the
 * selector.
 *
 * The 'funcs' field is used for application
 * specific functions.
 *
 * The EXTERN type uses a new style d2i/i2d.
 * The new style should be used where possible
 * because it avoids things like the d2i IMPLICIT
 * hack.
 *
 * MSTRING is a multiple string type, it is used
 * for a CHOICE of character strings where the
 * actual strings all occupy an YASN1_STRING
 * structure. In this case the 'utype' field
 * has a special meaning, it is used as a mask
 * of acceptable types using the B_YASN1 constants.
 *
 * NDEF_SEQUENCE is the same as SEQUENCE except
 * that it will use indefinite length constructed
 * encoding if requested.
 *
 */

# define YASN1_ITYPE_PRIMITIVE            0x0

# define YASN1_ITYPE_SEQUENCE             0x1

# define YASN1_ITYPE_CHOICE               0x2

# define YASN1_ITYPE_EXTERN               0x4

# define YASN1_ITYPE_MSTRING              0x5

# define YASN1_ITYPE_NDEF_SEQUENCE        0x6

/*
 * Cache for YASN1 tag and length, so we don't keep re-reading it for things
 * like CHOICE
 */

struct YASN1_TLC_st {
    char valid;                 /* Values below are valid */
    int ret;                    /* return value */
    long plen;                  /* length */
    int ptag;                   /* class value */
    int pclass;                 /* class value */
    int hdrlen;                 /* header length */
};

/* Typedefs for YASN1 function pointers */
typedef int YASN1_ex_d2i(YASN1_VALUE **pval, const unsigned char **in, long len,
                        const YASN1_ITEM *it, int tag, int aclass, char opt,
                        YASN1_TLC *ctx);

typedef int YASN1_ex_i2d(YASN1_VALUE **pval, unsigned char **out,
                        const YASN1_ITEM *it, int tag, int aclass);
typedef int YASN1_ex_new_func(YASN1_VALUE **pval, const YASN1_ITEM *it);
typedef void YASN1_ex_free_func(YASN1_VALUE **pval, const YASN1_ITEM *it);

typedef int YASN1_ex_print_func(BIO *out, YASN1_VALUE **pval,
                               int indent, const char *fname,
                               const YASN1_PCTX *pctx);

typedef int YASN1_primitive_i2c(YASN1_VALUE **pval, unsigned char *cont,
                               int *putype, const YASN1_ITEM *it);
typedef int YASN1_primitive_c2i(YASN1_VALUE **pval, const unsigned char *cont,
                               int len, int utype, char *free_cont,
                               const YASN1_ITEM *it);
typedef int YASN1_primitive_print(BIO *out, YASN1_VALUE **pval,
                                 const YASN1_ITEM *it, int indent,
                                 const YASN1_PCTX *pctx);

typedef struct YASN1_EXTERN_FUNCS_st {
    void *app_data;
    YASN1_ex_new_func *asn1_ex_new;
    YASN1_ex_free_func *asn1_ex_free;
    YASN1_ex_free_func *asn1_ex_clear;
    YASN1_ex_d2i *asn1_ex_d2i;
    YASN1_ex_i2d *asn1_ex_i2d;
    YASN1_ex_print_func *asn1_ex_print;
} YASN1_EXTERN_FUNCS;

typedef struct YASN1_PRIMITIVE_FUNCS_st {
    void *app_data;
    unsigned long flags;
    YASN1_ex_new_func *prim_new;
    YASN1_ex_free_func *prim_free;
    YASN1_ex_free_func *prim_clear;
    YASN1_primitive_c2i *prim_c2i;
    YASN1_primitive_i2c *prim_i2c;
    YASN1_primitive_print *prim_print;
} YASN1_PRIMITIVE_FUNCS;

/*
 * This is the YASN1_AUX structure: it handles various miscellaneous
 * requirements. For example the use of reference counts and an informational
 * callback. The "informational callback" is called at various points during
 * the YASN1 encoding and decoding. It can be used to provide minor
 * customisation of the structures used. This is most useful where the
 * supplied routines *almost* do the right thing but need some extra help at
 * a few points. If the callback returns zero then it is assumed a fatal
 * error has occurred and the main operation should be abandoned. If major
 * changes in the default behaviour are required then an external type is
 * more appropriate.
 */

typedef int YASN1_aux_cb(int operation, YASN1_VALUE **in, const YASN1_ITEM *it,
                        void *exarg);

typedef struct YASN1_AUX_st {
    void *app_data;
    int flags;
    int ref_offset;             /* Offset of reference value */
    int ref_lock;               /* Lock type to use */
    YASN1_aux_cb *asn1_cb;
    int enc_offset;             /* Offset of YASN1_ENCODING structure */
} YASN1_AUX;

/* For print related callbacks exarg points to this structure */
typedef struct YASN1_PRINT_ARG_st {
    BIO *out;
    int indent;
    const YASN1_PCTX *pctx;
} YASN1_PRINT_ARG;

/* For streaming related callbacks exarg points to this structure */
typedef struct YASN1_STREAM_ARG_st {
    /* BIO to stream through */
    BIO *out;
    /* BIO with filters appended */
    BIO *ndef_bio;
    /* Streaming I/O boundary */
    unsigned char **boundary;
} YASN1_STREAM_ARG;

/* Flags in YASN1_AUX */

/* Use a reference count */
# define YASN1_AFLG_REFCOUNT      1
/* Save the encoding of structure (useful for signatures) */
# define YASN1_AFLG_ENCODING      2
/* The Sequence length is invalid */
# define YASN1_AFLG_BROKEN        4

/* operation values for asn1_cb */

# define YASN1_OP_NEW_PRE         0
# define YASN1_OP_NEW_POST        1
# define YASN1_OP_FREE_PRE        2
# define YASN1_OP_FREE_POST       3
# define YASN1_OP_D2I_PRE         4
# define YASN1_OP_D2I_POST        5
# define YASN1_OP_I2D_PRE         6
# define YASN1_OP_I2D_POST        7
# define YASN1_OP_PRINT_PRE       8
# define YASN1_OP_PRINT_POST      9
# define YASN1_OP_STREAM_PRE      10
# define YASN1_OP_STREAM_POST     11
# define YASN1_OP_DETACHED_PRE    12
# define YASN1_OP_DETACHED_POST   13

/* Macro to implement a primitive type */
# define IMPLEMENT_YASN1_TYPE(stname) IMPLEMENT_YASN1_TYPE_ex(stname, stname, 0)
# define IMPLEMENT_YASN1_TYPE_ex(itname, vname, ex) \
                                YASN1_ITEM_start(itname) \
                                        YASN1_ITYPE_PRIMITIVE, V_##vname, NULL, 0, NULL, ex, #itname \
                                YASN1_ITEM_end(itname)

/* Macro to implement a multi string type */
# define IMPLEMENT_YASN1_MSTRING(itname, mask) \
                                YASN1_ITEM_start(itname) \
                                        YASN1_ITYPE_MSTRING, mask, NULL, 0, NULL, sizeof(YASN1_STRING), #itname \
                                YASN1_ITEM_end(itname)

# define IMPLEMENT_EXTERN_YASN1(sname, tag, fptrs) \
        YASN1_ITEM_start(sname) \
                YASN1_ITYPE_EXTERN, \
                tag, \
                NULL, \
                0, \
                &fptrs, \
                0, \
                #sname \
        YASN1_ITEM_end(sname)

/* Macro to implement standard functions in terms of YASN1_ITEM structures */

# define IMPLEMENT_YASN1_FUNCTIONS(stname) IMPLEMENT_YASN1_FUNCTIONS_fname(stname, stname, stname)

# define IMPLEMENT_YASN1_FUNCTIONS_name(stname, itname) IMPLEMENT_YASN1_FUNCTIONS_fname(stname, itname, itname)

# define IMPLEMENT_YASN1_FUNCTIONS_ENCODE_name(stname, itname) \
                        IMPLEMENT_YASN1_FUNCTIONS_ENCODE_fname(stname, itname, itname)

# define IMPLEMENT_STATIC_YASN1_ALLOC_FUNCTIONS(stname) \
                IMPLEMENT_YASN1_ALLOC_FUNCTIONS_pfname(static, stname, stname, stname)

# define IMPLEMENT_YASN1_ALLOC_FUNCTIONS(stname) \
                IMPLEMENT_YASN1_ALLOC_FUNCTIONS_fname(stname, stname, stname)

# define IMPLEMENT_YASN1_ALLOC_FUNCTIONS_pfname(pre, stname, itname, fname) \
        pre stname *fname##_new(void) \
        { \
                return (stname *)YASN1_item_new(YASN1_ITEM_rptr(itname)); \
        } \
        pre void fname##_free(stname *a) \
        { \
                YASN1_item_free((YASN1_VALUE *)a, YASN1_ITEM_rptr(itname)); \
        }

# define IMPLEMENT_YASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname) \
        stname *fname##_new(void) \
        { \
                return (stname *)YASN1_item_new(YASN1_ITEM_rptr(itname)); \
        } \
        void fname##_free(stname *a) \
        { \
                YASN1_item_free((YASN1_VALUE *)a, YASN1_ITEM_rptr(itname)); \
        }

# define IMPLEMENT_YASN1_FUNCTIONS_fname(stname, itname, fname) \
        IMPLEMENT_YASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        IMPLEMENT_YASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)

# define IMPLEMENT_YASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
        { \
                return (stname *)YASN1_item_d2i((YASN1_VALUE **)a, in, len, YASN1_ITEM_rptr(itname));\
        } \
        int i2d_##fname(stname *a, unsigned char **out) \
        { \
                return YASN1_item_i2d((YASN1_VALUE *)a, out, YASN1_ITEM_rptr(itname));\
        }

# define IMPLEMENT_YASN1_NDEF_FUNCTION(stname) \
        int i2d_##stname##_NDEF(stname *a, unsigned char **out) \
        { \
                return YASN1_item_ndef_i2d((YASN1_VALUE *)a, out, YASN1_ITEM_rptr(stname));\
        }

# define IMPLEMENT_STATIC_YASN1_ENCODE_FUNCTIONS(stname) \
        static stname *d2i_##stname(stname **a, \
                                   const unsigned char **in, long len) \
        { \
                return (stname *)YASN1_item_d2i((YASN1_VALUE **)a, in, len, \
                                               YASN1_ITEM_rptr(stname)); \
        } \
        static int i2d_##stname(stname *a, unsigned char **out) \
        { \
                return YASN1_item_i2d((YASN1_VALUE *)a, out, \
                                     YASN1_ITEM_rptr(stname)); \
        }

/*
 * This includes evil casts to remove const: they will go away when full YASN1
 * constification is done.
 */
# define IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) \
        stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
        { \
                return (stname *)YASN1_item_d2i((YASN1_VALUE **)a, in, len, YASN1_ITEM_rptr(itname));\
        } \
        int i2d_##fname(const stname *a, unsigned char **out) \
        { \
                return YASN1_item_i2d((YASN1_VALUE *)a, out, YASN1_ITEM_rptr(itname));\
        }

# define IMPLEMENT_YASN1_DUP_FUNCTION(stname) \
        stname * stname##_dup(stname *x) \
        { \
        return YASN1_item_dup(YASN1_ITEM_rptr(stname), x); \
        }

# define IMPLEMENT_YASN1_PRINT_FUNCTION(stname) \
        IMPLEMENT_YASN1_PRINT_FUNCTION_fname(stname, stname, stname)

# define IMPLEMENT_YASN1_PRINT_FUNCTION_fname(stname, itname, fname) \
        int fname##_print_ctx(BIO *out, stname *x, int indent, \
                                                const YASN1_PCTX *pctx) \
        { \
                return YASN1_item_print(out, (YASN1_VALUE *)x, indent, \
                        YASN1_ITEM_rptr(itname), pctx); \
        }

# define IMPLEMENT_YASN1_FUNCTIONS_const(name) \
                IMPLEMENT_YASN1_FUNCTIONS_const_fname(name, name, name)

# define IMPLEMENT_YASN1_FUNCTIONS_const_fname(stname, itname, fname) \
        IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) \
        IMPLEMENT_YASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)

/* external definitions for primitive types */

DECLARE_YASN1_ITEM(YASN1_BOOLEAN)
DECLARE_YASN1_ITEM(YASN1_TBOOLEAN)
DECLARE_YASN1_ITEM(YASN1_FBOOLEAN)
DECLARE_YASN1_ITEM(YASN1_SEQUENCE)
DECLARE_YASN1_ITEM(CBIGNUM)
DECLARE_YASN1_ITEM(BIGNUM)
DECLARE_YASN1_ITEM(INT32)
DECLARE_YASN1_ITEM(ZINT32)
DECLARE_YASN1_ITEM(UINT32)
DECLARE_YASN1_ITEM(ZUINT32)
DECLARE_YASN1_ITEM(INT64)
DECLARE_YASN1_ITEM(ZINT64)
DECLARE_YASN1_ITEM(UINT64)
DECLARE_YASN1_ITEM(ZUINT64)

# if OPENSSL_API_COMPAT < 0x10200000L
/*
 * LONG and ZLONG are strongly discouraged for use as stored data, as the
 * underlying C type (long) differs in size depending on the architecture.
 * They are designed with 32-bit longs in mind.
 */
DECLARE_YASN1_ITEM(LONG)
DECLARE_YASN1_ITEM(ZLONG)
# endif

DEFINE_STACK_OF(YASN1_VALUE)

/* Functions used internally by the YASN1 code */

int YASN1_item_ex_new(YASN1_VALUE **pval, const YASN1_ITEM *it);
void YASN1_item_ex_free(YASN1_VALUE **pval, const YASN1_ITEM *it);

int YASN1_item_ex_d2i(YASN1_VALUE **pval, const unsigned char **in, long len,
                     const YASN1_ITEM *it, int tag, int aclass, char opt,
                     YASN1_TLC *ctx);

int YASN1_item_ex_i2d(YASN1_VALUE **pval, unsigned char **out,
                     const YASN1_ITEM *it, int tag, int aclass);

#ifdef  __cplusplus
}
#endif
#endif
