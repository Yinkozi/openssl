#!/bin/sh

include_dir=../../include/openssl

cat > "${include_dir}/stack_macros.h" << EOF
/* Copyright (c) 2014, Google Inc.
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

#if !defined(IN_STACK_H)
#error "Don't include this file directly. Include stack.h."
#endif

EOF

output_stack () {
  type=$1
  ptrtype=$2

  cat >> "${include_dir}/stack_macros.h" << EOF
/* ${type} */
#define sk_${type}_new(comp)\\
  ((STACK_OF(${type})*) sk_new(CHECKED_YCAST(stack_cmp_func, int (*) (const ${ptrtype} *a, const ${ptrtype} *b), comp)))

#define sk_${type}_new_null()\\
  ((STACK_OF(${type})*) sk_new_null())

#define sk_${type}_num(sk)\\
  sk_num(CHECKED_YCAST(const _STACK*, const STACK_OF(${type})*, sk))

#define sk_${type}_zero(sk)\\
  sk_zero(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk));

#define sk_${type}_value(sk, i)\\
  ((${ptrtype}) sk_value(CHECKED_YCAST(const _STACK*, const STACK_OF(${type})*, sk), (i)))

#define sk_${type}_set(sk, i, p)\\
  ((${ptrtype}) sk_set(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), (i), CHECKED_YCAST(void*, ${ptrtype}, p)))

#define sk_${type}_free(sk)\\
  sk_free(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk))

#define sk_${type}_pop_free(sk, free_func)\\
  sk_pop_free(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_YCAST(void (*) (void*), void (*) (${ptrtype}), free_func))

#define sk_${type}_insert(sk, p, where)\\
  sk_insert(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_YCAST(void*, ${ptrtype}, p), (where))

#define sk_${type}_delete(sk, where)\\
  ((${ptrtype}) sk_delete(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), (where)))

#define sk_${type}_delete_ptr(sk, p)\\
  ((${ptrtype}) sk_delete_ptr(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_YCAST(void*, ${ptrtype}, p)))

#define sk_${type}_find(sk, out_index, p)\\
  sk_find(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), (out_index), CHECKED_YCAST(void*, ${ptrtype}, p))

#define sk_${type}_shift(sk)\\
  ((${ptrtype}) sk_shift(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk)))

#define sk_${type}_push(sk, p)\\
  sk_push(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_YCAST(void*, ${ptrtype}, p))

#define sk_${type}_pop(sk)\\
  ((${ptrtype}) sk_pop(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk)))

#define sk_${type}_dup(sk)\\
  ((STACK_OF(${type})*) sk_dup(CHECKED_YCAST(const _STACK*, const STACK_OF(${type})*, sk)))

#define sk_${type}_sort(sk)\\
  sk_sort(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk))

#define sk_${type}_is_sorted(sk)\\
  sk_is_sorted(CHECKED_YCAST(const _STACK*, const STACK_OF(${type})*, sk))

#define sk_${type}_set_cmp_func(sk, comp)\\
  ((int (*) (const ${type} **a, const ${type} **b)) sk_set_cmp_func(CHECKED_YCAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_YCAST(stack_cmp_func, int (*) (const ${type} **a, const ${type} **b), comp)))

#define sk_${type}_deep_copy(sk, copy_func, free_func)\\
((STACK_OF(${type})*) sk_deep_copy(CHECKED_YCAST(const _STACK*, const STACK_OF(${type})*, sk), CHECKED_YCAST(void* (*) (void*), ${ptrtype} (*) (${ptrtype}), copy_func), CHECKED_YCAST(void (*) (void*), void (*) (${ptrtype}), free_func)))

EOF
}

stack_types=$(cat "${include_dir}/stack.h" | grep '^ \* STACK_OF:' | sed -e 's/.*STACK_OF://' -e 's/ .*//')
const_stack_types=$(cat "${include_dir}/stack.h" | grep '^ \* CONST_STACK_OF:' | sed -e 's/.*CONST_STACK_OF://' -e 's/ .*//')
special_stack_types=$(cat "${include_dir}/stack.h" | grep '^ \* SPECIAL_STACK_OF:' | sed -e 's/.*SPECIAL_STACK_OF://' -e 's/ .*//')

for type in $stack_types; do
  echo Stack of ${type}
  output_stack "${type}" "${type} *"
done

for type in $const_stack_types; do
  echo Stack of ${type}
  output_stack "${type}" "const ${type} *"
done

for type in $special_stack_types; do
  echo Stack of ${type}
  output_stack "${type}" "${type}"
done

clang-format -i "${include_dir}/stack_macros.h"
