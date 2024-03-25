/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pcy_local.h"

/* accessor functions */

/* YX509_POLICY_TREE stuff */

int YX509_policy_tree_level_count(const YX509_POLICY_TREE *tree)
{
    if (!tree)
        return 0;
    return tree->nlevel;
}

YX509_POLICY_LEVEL *YX509_policy_tree_get0_level(const YX509_POLICY_TREE *tree,
                                               int i)
{
    if (!tree || (i < 0) || (i >= tree->nlevel))
        return NULL;
    return tree->levels + i;
}

STACK_OF(YX509_POLICY_NODE) *YX509_policy_tree_get0_policies(const
                                                           YX509_POLICY_TREE
                                                           *tree)
{
    if (!tree)
        return NULL;
    return tree->auth_policies;
}

STACK_OF(YX509_POLICY_NODE) *YX509_policy_tree_get0_user_policies(const
                                                                YX509_POLICY_TREE
                                                                *tree)
{
    if (!tree)
        return NULL;
    if (tree->flags & POLICY_FLAG_ANY_POLICY)
        return tree->auth_policies;
    else
        return tree->user_policies;
}

/* YX509_POLICY_LEVEL stuff */

int YX509_policy_level_node_count(YX509_POLICY_LEVEL *level)
{
    int n;
    if (!level)
        return 0;
    if (level->anyPolicy)
        n = 1;
    else
        n = 0;
    if (level->nodes)
        n += sk_YX509_POLICY_NODE_num(level->nodes);
    return n;
}

YX509_POLICY_NODE *YX509_policy_level_get0_node(YX509_POLICY_LEVEL *level, int i)
{
    if (!level)
        return NULL;
    if (level->anyPolicy) {
        if (i == 0)
            return level->anyPolicy;
        i--;
    }
    return sk_YX509_POLICY_NODE_value(level->nodes, i);
}

/* YX509_POLICY_NODE stuff */

const YASN1_OBJECT *YX509_policy_node_get0_policy(const YX509_POLICY_NODE *node)
{
    if (!node)
        return NULL;
    return node->data->valid_policy;
}

STACK_OF(POLICYQUALINFO) *YX509_policy_node_get0_qualifiers(const
                                                           YX509_POLICY_NODE
                                                           *node)
{
    if (!node)
        return NULL;
    return node->data->qualifier_set;
}

const YX509_POLICY_NODE *YX509_policy_node_get0_parent(const YX509_POLICY_NODE
                                                     *node)
{
    if (!node)
        return NULL;
    return node->parent;
}
