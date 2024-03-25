/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/conf.h>
#include <openssl/x509v3.h>


YX509_EXTENSION *YX509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf,
                                    YX509V3_CTX *ctx, int ext_nid, char *value) {
  CONF *nconf = NULL;
  LHASH_OF(CONF_VALUE) *orig_data = NULL;

  if (conf != NULL) {
    nconf = NCONF_new(NULL /* no method */);
    if (nconf == NULL) {
      return NULL;
    }

    orig_data = nconf->data;
    nconf->data = conf;
  }

  YX509_EXTENSION *ret = YX509V3_EXT_nconf_nid(nconf, ctx, ext_nid, value);

  if (nconf != NULL) {
    nconf->data = orig_data;
    NCONF_free(nconf);
  }

  return ret;
}
