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

/* ACCESS_DESCRIPTION */
#define sk_ACCESS_DESCRIPTION_new(comp)                                    \
  ((STACK_OF(ACCESS_DESCRIPTION) *)sk_new(CHECKED_YCAST(                    \
      stack_cmp_func,                                                      \
      int (*)(const ACCESS_DESCRIPTION **a, const ACCESS_DESCRIPTION **b), \
      comp)))

#define sk_ACCESS_DESCRIPTION_new_null() \
  ((STACK_OF(ACCESS_DESCRIPTION) *)sk_new_null())

#define sk_ACCESS_DESCRIPTION_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(ACCESS_DESCRIPTION) *, sk))

#define sk_ACCESS_DESCRIPTION_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk));

#define sk_ACCESS_DESCRIPTION_value(sk, i)                                    \
  ((ACCESS_DESCRIPTION *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(ACCESS_DESCRIPTION) *, sk), \
      (i)))

#define sk_ACCESS_DESCRIPTION_set(sk, i, p)                            \
  ((ACCESS_DESCRIPTION *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), (i), \
      CHECKED_YCAST(void *, ACCESS_DESCRIPTION *, p)))

#define sk_ACCESS_DESCRIPTION_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk))

#define sk_ACCESS_DESCRIPTION_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(ACCESS_DESCRIPTION *), \
                           free_func))

#define sk_ACCESS_DESCRIPTION_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), \
            CHECKED_YCAST(void *, ACCESS_DESCRIPTION *, p), (where))

#define sk_ACCESS_DESCRIPTION_delete(sk, where) \
  ((ACCESS_DESCRIPTION *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), (where)))

#define sk_ACCESS_DESCRIPTION_delete_ptr(sk, p)                   \
  ((ACCESS_DESCRIPTION *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), \
      CHECKED_YCAST(void *, ACCESS_DESCRIPTION *, p)))

#define sk_ACCESS_DESCRIPTION_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), \
          (out_index), CHECKED_YCAST(void *, ACCESS_DESCRIPTION *, p))

#define sk_ACCESS_DESCRIPTION_shift(sk) \
  ((ACCESS_DESCRIPTION *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk)))

#define sk_ACCESS_DESCRIPTION_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk), \
          CHECKED_YCAST(void *, ACCESS_DESCRIPTION *, p))

#define sk_ACCESS_DESCRIPTION_pop(sk) \
  ((ACCESS_DESCRIPTION *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk)))

#define sk_ACCESS_DESCRIPTION_dup(sk)      \
  ((STACK_OF(ACCESS_DESCRIPTION) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(ACCESS_DESCRIPTION) *, sk)))

#define sk_ACCESS_DESCRIPTION_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk))

#define sk_ACCESS_DESCRIPTION_is_sorted(sk) \
  sk_is_sorted(                             \
      CHECKED_YCAST(const _STACK *, const STACK_OF(ACCESS_DESCRIPTION) *, sk))

#define sk_ACCESS_DESCRIPTION_set_cmp_func(sk, comp)                           \
  ((int (*)(const ACCESS_DESCRIPTION **a, const ACCESS_DESCRIPTION **b))       \
       sk_set_cmp_func(                                                        \
           CHECKED_YCAST(_STACK *, STACK_OF(ACCESS_DESCRIPTION) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const ACCESS_DESCRIPTION **a,  \
                                                const ACCESS_DESCRIPTION **b), \
                        comp)))

#define sk_ACCESS_DESCRIPTION_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(ACCESS_DESCRIPTION) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(ACCESS_DESCRIPTION) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                         \
                   ACCESS_DESCRIPTION *(*)(ACCESS_DESCRIPTION *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(ACCESS_DESCRIPTION *),          \
                   free_func)))

/* YASN1_ADB_TABLE */
#define sk_YASN1_ADB_TABLE_new(comp)                 \
  ((STACK_OF(YASN1_ADB_TABLE) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const YASN1_ADB_TABLE **a, const YASN1_ADB_TABLE **b), comp)))

#define sk_YASN1_ADB_TABLE_new_null() ((STACK_OF(YASN1_ADB_TABLE) *)sk_new_null())

#define sk_YASN1_ADB_TABLE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_ADB_TABLE) *, sk))

#define sk_YASN1_ADB_TABLE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk));

#define sk_YASN1_ADB_TABLE_value(sk, i)                                    \
  ((YASN1_ADB_TABLE *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_ADB_TABLE) *, sk), \
      (i)))

#define sk_YASN1_ADB_TABLE_set(sk, i, p)                            \
  ((YASN1_ADB_TABLE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), (i), \
      CHECKED_YCAST(void *, YASN1_ADB_TABLE *, p)))

#define sk_YASN1_ADB_TABLE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk))

#define sk_YASN1_ADB_TABLE_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_ADB_TABLE *), free_func))

#define sk_YASN1_ADB_TABLE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), \
            CHECKED_YCAST(void *, YASN1_ADB_TABLE *, p), (where))

#define sk_YASN1_ADB_TABLE_delete(sk, where) \
  ((YASN1_ADB_TABLE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), (where)))

#define sk_YASN1_ADB_TABLE_delete_ptr(sk, p)                   \
  ((YASN1_ADB_TABLE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), \
      CHECKED_YCAST(void *, YASN1_ADB_TABLE *, p)))

#define sk_YASN1_ADB_TABLE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), (out_index), \
          CHECKED_YCAST(void *, YASN1_ADB_TABLE *, p))

#define sk_YASN1_ADB_TABLE_shift(sk) \
  ((YASN1_ADB_TABLE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk)))

#define sk_YASN1_ADB_TABLE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk), \
          CHECKED_YCAST(void *, YASN1_ADB_TABLE *, p))

#define sk_YASN1_ADB_TABLE_pop(sk) \
  ((YASN1_ADB_TABLE *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk)))

#define sk_YASN1_ADB_TABLE_dup(sk)      \
  ((STACK_OF(YASN1_ADB_TABLE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_ADB_TABLE) *, sk)))

#define sk_YASN1_ADB_TABLE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk))

#define sk_YASN1_ADB_TABLE_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_ADB_TABLE) *, sk))

#define sk_YASN1_ADB_TABLE_set_cmp_func(sk, comp)                           \
  ((int (*)(const YASN1_ADB_TABLE **a, const YASN1_ADB_TABLE **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(YASN1_ADB_TABLE) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YASN1_ADB_TABLE **a,  \
                                                const YASN1_ADB_TABLE **b), \
                        comp)))

#define sk_YASN1_ADB_TABLE_deep_copy(sk, copy_func, free_func)                \
  ((STACK_OF(YASN1_ADB_TABLE) *)sk_deep_copy(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_ADB_TABLE) *, sk),    \
      CHECKED_YCAST(void *(*)(void *), YASN1_ADB_TABLE *(*)(YASN1_ADB_TABLE *), \
                   copy_func),                                               \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_ADB_TABLE *), free_func)))

/* YASN1_GENERALSTRING */
#define sk_YASN1_GENERALSTRING_new(comp)                                    \
  ((STACK_OF(YASN1_GENERALSTRING) *)sk_new(CHECKED_YCAST(                    \
      stack_cmp_func,                                                      \
      int (*)(const YASN1_GENERALSTRING **a, const YASN1_GENERALSTRING **b), \
      comp)))

#define sk_YASN1_GENERALSTRING_new_null() \
  ((STACK_OF(YASN1_GENERALSTRING) *)sk_new_null())

#define sk_YASN1_GENERALSTRING_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_GENERALSTRING) *, sk))

#define sk_YASN1_GENERALSTRING_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk));

#define sk_YASN1_GENERALSTRING_value(sk, i)                                    \
  ((YASN1_GENERALSTRING *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_GENERALSTRING) *, sk), \
      (i)))

#define sk_YASN1_GENERALSTRING_set(sk, i, p)                            \
  ((YASN1_GENERALSTRING *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), (i), \
      CHECKED_YCAST(void *, YASN1_GENERALSTRING *, p)))

#define sk_YASN1_GENERALSTRING_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk))

#define sk_YASN1_GENERALSTRING_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(YASN1_GENERALSTRING *), \
                           free_func))

#define sk_YASN1_GENERALSTRING_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), \
            CHECKED_YCAST(void *, YASN1_GENERALSTRING *, p), (where))

#define sk_YASN1_GENERALSTRING_delete(sk, where) \
  ((YASN1_GENERALSTRING *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), (where)))

#define sk_YASN1_GENERALSTRING_delete_ptr(sk, p)                   \
  ((YASN1_GENERALSTRING *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), \
      CHECKED_YCAST(void *, YASN1_GENERALSTRING *, p)))

#define sk_YASN1_GENERALSTRING_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), \
          (out_index), CHECKED_YCAST(void *, YASN1_GENERALSTRING *, p))

#define sk_YASN1_GENERALSTRING_shift(sk) \
  ((YASN1_GENERALSTRING *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk)))

#define sk_YASN1_GENERALSTRING_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk), \
          CHECKED_YCAST(void *, YASN1_GENERALSTRING *, p))

#define sk_YASN1_GENERALSTRING_pop(sk) \
  ((YASN1_GENERALSTRING *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk)))

#define sk_YASN1_GENERALSTRING_dup(sk)      \
  ((STACK_OF(YASN1_GENERALSTRING) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_GENERALSTRING) *, sk)))

#define sk_YASN1_GENERALSTRING_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk))

#define sk_YASN1_GENERALSTRING_is_sorted(sk) \
  sk_is_sorted(                             \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_GENERALSTRING) *, sk))

#define sk_YASN1_GENERALSTRING_set_cmp_func(sk, comp)                           \
  ((int (*)(const YASN1_GENERALSTRING **a, const YASN1_GENERALSTRING **b))       \
       sk_set_cmp_func(                                                        \
           CHECKED_YCAST(_STACK *, STACK_OF(YASN1_GENERALSTRING) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YASN1_GENERALSTRING **a,  \
                                                const YASN1_GENERALSTRING **b), \
                        comp)))

#define sk_YASN1_GENERALSTRING_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YASN1_GENERALSTRING) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_GENERALSTRING) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                         \
                   YASN1_GENERALSTRING *(*)(YASN1_GENERALSTRING *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_GENERALSTRING *),          \
                   free_func)))

/* YASN1_INTEGER */
#define sk_YASN1_INTEGER_new(comp)                                              \
  ((STACK_OF(YASN1_INTEGER) *)sk_new(CHECKED_YCAST(                              \
      stack_cmp_func, int (*)(const YASN1_INTEGER **a, const YASN1_INTEGER **b), \
      comp)))

#define sk_YASN1_INTEGER_new_null() ((STACK_OF(YASN1_INTEGER) *)sk_new_null())

#define sk_YASN1_INTEGER_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_INTEGER) *, sk))

#define sk_YASN1_INTEGER_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk));

#define sk_YASN1_INTEGER_value(sk, i) \
  ((YASN1_INTEGER *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_INTEGER) *, sk), (i)))

#define sk_YASN1_INTEGER_set(sk, i, p)                            \
  ((YASN1_INTEGER *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), (i), \
      CHECKED_YCAST(void *, YASN1_INTEGER *, p)))

#define sk_YASN1_INTEGER_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk))

#define sk_YASN1_INTEGER_pop_free(sk, free_func)             \
  sk_pop_free(                                              \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_INTEGER *), free_func))

#define sk_YASN1_INTEGER_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), \
            CHECKED_YCAST(void *, YASN1_INTEGER *, p), (where))

#define sk_YASN1_INTEGER_delete(sk, where) \
  ((YASN1_INTEGER *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), (where)))

#define sk_YASN1_INTEGER_delete_ptr(sk, p)                   \
  ((YASN1_INTEGER *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), \
      CHECKED_YCAST(void *, YASN1_INTEGER *, p)))

#define sk_YASN1_INTEGER_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), (out_index), \
          CHECKED_YCAST(void *, YASN1_INTEGER *, p))

#define sk_YASN1_INTEGER_shift(sk) \
  ((YASN1_INTEGER *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk)))

#define sk_YASN1_INTEGER_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk), \
          CHECKED_YCAST(void *, YASN1_INTEGER *, p))

#define sk_YASN1_INTEGER_pop(sk) \
  ((YASN1_INTEGER *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk)))

#define sk_YASN1_INTEGER_dup(sk)      \
  ((STACK_OF(YASN1_INTEGER) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_INTEGER) *, sk)))

#define sk_YASN1_INTEGER_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk))

#define sk_YASN1_INTEGER_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_INTEGER) *, sk))

#define sk_YASN1_INTEGER_set_cmp_func(sk, comp)                               \
  ((int (*)(const YASN1_INTEGER **a, const YASN1_INTEGER **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_INTEGER) *, sk),                  \
      CHECKED_YCAST(stack_cmp_func,                                           \
                   int (*)(const YASN1_INTEGER **a, const YASN1_INTEGER **b),  \
                   comp)))

#define sk_YASN1_INTEGER_deep_copy(sk, copy_func, free_func)              \
  ((STACK_OF(YASN1_INTEGER) *)sk_deep_copy(                               \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_INTEGER) *, sk),  \
      CHECKED_YCAST(void *(*)(void *), YASN1_INTEGER *(*)(YASN1_INTEGER *), \
                   copy_func),                                           \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_INTEGER *), free_func)))

/* YASN1_OBJECT */
#define sk_YASN1_OBJECT_new(comp)                                             \
  ((STACK_OF(YASN1_OBJECT) *)sk_new(CHECKED_YCAST(                             \
      stack_cmp_func, int (*)(const YASN1_OBJECT **a, const YASN1_OBJECT **b), \
      comp)))

#define sk_YASN1_OBJECT_new_null() ((STACK_OF(YASN1_OBJECT) *)sk_new_null())

#define sk_YASN1_OBJECT_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_OBJECT) *, sk))

#define sk_YASN1_OBJECT_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk));

#define sk_YASN1_OBJECT_value(sk, i) \
  ((YASN1_OBJECT *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_OBJECT) *, sk), (i)))

#define sk_YASN1_OBJECT_set(sk, i, p)                                          \
  ((YASN1_OBJECT *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), \
                         (i), CHECKED_YCAST(void *, YASN1_OBJECT *, p)))

#define sk_YASN1_OBJECT_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk))

#define sk_YASN1_OBJECT_pop_free(sk, free_func)             \
  sk_pop_free(                                             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_OBJECT *), free_func))

#define sk_YASN1_OBJECT_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), \
            CHECKED_YCAST(void *, YASN1_OBJECT *, p), (where))

#define sk_YASN1_OBJECT_delete(sk, where) \
  ((YASN1_OBJECT *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), (where)))

#define sk_YASN1_OBJECT_delete_ptr(sk, p)                   \
  ((YASN1_OBJECT *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), \
      CHECKED_YCAST(void *, YASN1_OBJECT *, p)))

#define sk_YASN1_OBJECT_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), (out_index), \
          CHECKED_YCAST(void *, YASN1_OBJECT *, p))

#define sk_YASN1_OBJECT_shift(sk) \
  ((YASN1_OBJECT *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk)))

#define sk_YASN1_OBJECT_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk), \
          CHECKED_YCAST(void *, YASN1_OBJECT *, p))

#define sk_YASN1_OBJECT_pop(sk) \
  ((YASN1_OBJECT *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk)))

#define sk_YASN1_OBJECT_dup(sk)      \
  ((STACK_OF(YASN1_OBJECT) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_OBJECT) *, sk)))

#define sk_YASN1_OBJECT_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk))

#define sk_YASN1_OBJECT_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_OBJECT) *, sk))

#define sk_YASN1_OBJECT_set_cmp_func(sk, comp)                              \
  ((int (*)(const YASN1_OBJECT **a, const YASN1_OBJECT **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_OBJECT) *, sk),                 \
      CHECKED_YCAST(stack_cmp_func,                                         \
                   int (*)(const YASN1_OBJECT **a, const YASN1_OBJECT **b),  \
                   comp)))

#define sk_YASN1_OBJECT_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YASN1_OBJECT) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_OBJECT) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YASN1_OBJECT *(*)(YASN1_OBJECT *), \
                   copy_func),                                         \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_OBJECT *), free_func)))

/* YASN1_STRING_TABLE */
#define sk_YASN1_STRING_TABLE_new(comp)                                   \
  ((STACK_OF(YASN1_STRING_TABLE) *)sk_new(CHECKED_YCAST(                   \
      stack_cmp_func,                                                    \
      int (*)(const YASN1_STRING_TABLE **a, const YASN1_STRING_TABLE **b), \
      comp)))

#define sk_YASN1_STRING_TABLE_new_null() \
  ((STACK_OF(YASN1_STRING_TABLE) *)sk_new_null())

#define sk_YASN1_STRING_TABLE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_STRING_TABLE) *, sk))

#define sk_YASN1_STRING_TABLE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk));

#define sk_YASN1_STRING_TABLE_value(sk, i)                                    \
  ((YASN1_STRING_TABLE *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_STRING_TABLE) *, sk), \
      (i)))

#define sk_YASN1_STRING_TABLE_set(sk, i, p)                            \
  ((YASN1_STRING_TABLE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), (i), \
      CHECKED_YCAST(void *, YASN1_STRING_TABLE *, p)))

#define sk_YASN1_STRING_TABLE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk))

#define sk_YASN1_STRING_TABLE_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(YASN1_STRING_TABLE *), \
                           free_func))

#define sk_YASN1_STRING_TABLE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), \
            CHECKED_YCAST(void *, YASN1_STRING_TABLE *, p), (where))

#define sk_YASN1_STRING_TABLE_delete(sk, where) \
  ((YASN1_STRING_TABLE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), (where)))

#define sk_YASN1_STRING_TABLE_delete_ptr(sk, p)                   \
  ((YASN1_STRING_TABLE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), \
      CHECKED_YCAST(void *, YASN1_STRING_TABLE *, p)))

#define sk_YASN1_STRING_TABLE_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), \
          (out_index), CHECKED_YCAST(void *, YASN1_STRING_TABLE *, p))

#define sk_YASN1_STRING_TABLE_shift(sk) \
  ((YASN1_STRING_TABLE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk)))

#define sk_YASN1_STRING_TABLE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk), \
          CHECKED_YCAST(void *, YASN1_STRING_TABLE *, p))

#define sk_YASN1_STRING_TABLE_pop(sk) \
  ((YASN1_STRING_TABLE *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk)))

#define sk_YASN1_STRING_TABLE_dup(sk)      \
  ((STACK_OF(YASN1_STRING_TABLE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_STRING_TABLE) *, sk)))

#define sk_YASN1_STRING_TABLE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk))

#define sk_YASN1_STRING_TABLE_is_sorted(sk) \
  sk_is_sorted(                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_STRING_TABLE) *, sk))

#define sk_YASN1_STRING_TABLE_set_cmp_func(sk, comp)                           \
  ((int (*)(const YASN1_STRING_TABLE **a, const YASN1_STRING_TABLE **b))        \
       sk_set_cmp_func(                                                       \
           CHECKED_YCAST(_STACK *, STACK_OF(YASN1_STRING_TABLE) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YASN1_STRING_TABLE **a,  \
                                                const YASN1_STRING_TABLE **b), \
                        comp)))

#define sk_YASN1_STRING_TABLE_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YASN1_STRING_TABLE) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_STRING_TABLE) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                        \
                   YASN1_STRING_TABLE *(*)(YASN1_STRING_TABLE *), copy_func),  \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_STRING_TABLE *),          \
                   free_func)))

/* YASN1_TYPE */
#define sk_YASN1_TYPE_new(comp)     \
  ((STACK_OF(YASN1_TYPE) *)sk_new(  \
      CHECKED_YCAST(stack_cmp_func, \
                   int (*)(const YASN1_TYPE **a, const YASN1_TYPE **b), comp)))

#define sk_YASN1_TYPE_new_null() ((STACK_OF(YASN1_TYPE) *)sk_new_null())

#define sk_YASN1_TYPE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_TYPE) *, sk))

#define sk_YASN1_TYPE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk));

#define sk_YASN1_TYPE_value(sk, i) \
  ((YASN1_TYPE *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_TYPE) *, sk), (i)))

#define sk_YASN1_TYPE_set(sk, i, p)                                             \
  ((YASN1_TYPE *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), (i), \
                       CHECKED_YCAST(void *, YASN1_TYPE *, p)))

#define sk_YASN1_TYPE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk))

#define sk_YASN1_TYPE_pop_free(sk, free_func)             \
  sk_pop_free(                                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_TYPE *), free_func))

#define sk_YASN1_TYPE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), \
            CHECKED_YCAST(void *, YASN1_TYPE *, p), (where))

#define sk_YASN1_TYPE_delete(sk, where)                                       \
  ((YASN1_TYPE *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), \
                          (where)))

#define sk_YASN1_TYPE_delete_ptr(sk, p)                   \
  ((YASN1_TYPE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), \
      CHECKED_YCAST(void *, YASN1_TYPE *, p)))

#define sk_YASN1_TYPE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), (out_index), \
          CHECKED_YCAST(void *, YASN1_TYPE *, p))

#define sk_YASN1_TYPE_shift(sk) \
  ((YASN1_TYPE *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk)))

#define sk_YASN1_TYPE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk), \
          CHECKED_YCAST(void *, YASN1_TYPE *, p))

#define sk_YASN1_TYPE_pop(sk) \
  ((YASN1_TYPE *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk)))

#define sk_YASN1_TYPE_dup(sk)      \
  ((STACK_OF(YASN1_TYPE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_TYPE) *, sk)))

#define sk_YASN1_TYPE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk))

#define sk_YASN1_TYPE_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_TYPE) *, sk))

#define sk_YASN1_TYPE_set_cmp_func(sk, comp)                            \
  ((int (*)(const YASN1_TYPE **a, const YASN1_TYPE **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_TYPE) *, sk),               \
      CHECKED_YCAST(stack_cmp_func,                                     \
                   int (*)(const YASN1_TYPE **a, const YASN1_TYPE **b), comp)))

#define sk_YASN1_TYPE_deep_copy(sk, copy_func, free_func)                       \
  ((STACK_OF(YASN1_TYPE) *)sk_deep_copy(                                        \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_TYPE) *, sk),           \
      CHECKED_YCAST(void *(*)(void *), YASN1_TYPE *(*)(YASN1_TYPE *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_TYPE *), free_func)))

/* YASN1_VALUE */
#define sk_YASN1_VALUE_new(comp)                                            \
  ((STACK_OF(YASN1_VALUE) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const YASN1_VALUE **a, const YASN1_VALUE **b), \
      comp)))

#define sk_YASN1_VALUE_new_null() ((STACK_OF(YASN1_VALUE) *)sk_new_null())

#define sk_YASN1_VALUE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_VALUE) *, sk))

#define sk_YASN1_VALUE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk));

#define sk_YASN1_VALUE_value(sk, i) \
  ((YASN1_VALUE *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_VALUE) *, sk), (i)))

#define sk_YASN1_VALUE_set(sk, i, p)                                         \
  ((YASN1_VALUE *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
                        (i), CHECKED_YCAST(void *, YASN1_VALUE *, p)))

#define sk_YASN1_VALUE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk))

#define sk_YASN1_VALUE_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_VALUE *), free_func))

#define sk_YASN1_VALUE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
            CHECKED_YCAST(void *, YASN1_VALUE *, p), (where))

#define sk_YASN1_VALUE_delete(sk, where)                                        \
  ((YASN1_VALUE *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
                           (where)))

#define sk_YASN1_VALUE_delete_ptr(sk, p)                   \
  ((YASN1_VALUE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
      CHECKED_YCAST(void *, YASN1_VALUE *, p)))

#define sk_YASN1_VALUE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), (out_index), \
          CHECKED_YCAST(void *, YASN1_VALUE *, p))

#define sk_YASN1_VALUE_shift(sk) \
  ((YASN1_VALUE *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk)))

#define sk_YASN1_VALUE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk), \
          CHECKED_YCAST(void *, YASN1_VALUE *, p))

#define sk_YASN1_VALUE_pop(sk) \
  ((YASN1_VALUE *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk)))

#define sk_YASN1_VALUE_dup(sk)      \
  ((STACK_OF(YASN1_VALUE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_VALUE) *, sk)))

#define sk_YASN1_VALUE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk))

#define sk_YASN1_VALUE_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_VALUE) *, sk))

#define sk_YASN1_VALUE_set_cmp_func(sk, comp)                             \
  ((int (*)(const YASN1_VALUE **a, const YASN1_VALUE **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YASN1_VALUE) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const YASN1_VALUE **a, const YASN1_VALUE **b),  \
                   comp)))

#define sk_YASN1_VALUE_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YASN1_VALUE) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YASN1_VALUE) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YASN1_VALUE *(*)(YASN1_VALUE *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(YASN1_VALUE *), free_func)))

/* BIO */
#define sk_BIO_new(comp)                 \
  ((STACK_OF(BIO) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const BIO **a, const BIO **b), comp)))

#define sk_BIO_new_null() ((STACK_OF(BIO) *)sk_new_null())

#define sk_BIO_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(BIO) *, sk))

#define sk_BIO_zero(sk) sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk));

#define sk_BIO_value(sk, i)                                                 \
  ((BIO *)sk_value(CHECKED_YCAST(const _STACK *, const STACK_OF(BIO) *, sk), \
                   (i)))

#define sk_BIO_set(sk, i, p)                                       \
  ((BIO *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), (i), \
                 CHECKED_YCAST(void *, BIO *, p)))

#define sk_BIO_free(sk) sk_free(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk))

#define sk_BIO_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(BIO *), free_func))

#define sk_BIO_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), \
            CHECKED_YCAST(void *, BIO *, p), (where))

#define sk_BIO_delete(sk, where) \
  ((BIO *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), (where)))

#define sk_BIO_delete_ptr(sk, p)                                     \
  ((BIO *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), \
                        CHECKED_YCAST(void *, BIO *, p)))

#define sk_BIO_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), (out_index), \
          CHECKED_YCAST(void *, BIO *, p))

#define sk_BIO_shift(sk) \
  ((BIO *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk)))

#define sk_BIO_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk), \
          CHECKED_YCAST(void *, BIO *, p))

#define sk_BIO_pop(sk) \
  ((BIO *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk)))

#define sk_BIO_dup(sk)      \
  ((STACK_OF(BIO) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BIO) *, sk)))

#define sk_BIO_sort(sk) sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk))

#define sk_BIO_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(BIO) *, sk))

#define sk_BIO_set_cmp_func(sk, comp)                                     \
  ((int (*)(const BIO **a, const BIO **b))sk_set_cmp_func(                \
      CHECKED_YCAST(_STACK *, STACK_OF(BIO) *, sk),                        \
      CHECKED_YCAST(stack_cmp_func, int (*)(const BIO **a, const BIO **b), \
                   comp)))

#define sk_BIO_deep_copy(sk, copy_func, free_func)                 \
  ((STACK_OF(BIO) *)sk_deep_copy(                                  \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BIO) *, sk),     \
      CHECKED_YCAST(void *(*)(void *), BIO *(*)(BIO *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(BIO *), free_func)))

/* BY_DIR_ENTRY */
#define sk_BY_DIR_ENTRY_new(comp)                                              \
  ((STACK_OF(BY_DIR_ENTRY) *)sk_new(CHECKED_YCAST(                              \
      stack_cmp_func, int (*)(const BY_DIR_ENTRY **a, const BY_DIR_ENTRY **b), \
      comp)))

#define sk_BY_DIR_ENTRY_new_null() ((STACK_OF(BY_DIR_ENTRY) *)sk_new_null())

#define sk_BY_DIR_ENTRY_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_ENTRY) *, sk))

#define sk_BY_DIR_ENTRY_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk));

#define sk_BY_DIR_ENTRY_value(sk, i) \
  ((BY_DIR_ENTRY *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_ENTRY) *, sk), (i)))

#define sk_BY_DIR_ENTRY_set(sk, i, p)                            \
  ((BY_DIR_ENTRY *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), (i), \
      CHECKED_YCAST(void *, BY_DIR_ENTRY *, p)))

#define sk_BY_DIR_ENTRY_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk))

#define sk_BY_DIR_ENTRY_pop_free(sk, free_func)             \
  sk_pop_free(                                              \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(BY_DIR_ENTRY *), free_func))

#define sk_BY_DIR_ENTRY_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), \
            CHECKED_YCAST(void *, BY_DIR_ENTRY *, p), (where))

#define sk_BY_DIR_ENTRY_delete(sk, where) \
  ((BY_DIR_ENTRY *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), (where)))

#define sk_BY_DIR_ENTRY_delete_ptr(sk, p)                   \
  ((BY_DIR_ENTRY *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), \
      CHECKED_YCAST(void *, BY_DIR_ENTRY *, p)))

#define sk_BY_DIR_ENTRY_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), (out_index), \
          CHECKED_YCAST(void *, BY_DIR_ENTRY *, p))

#define sk_BY_DIR_ENTRY_shift(sk) \
  ((BY_DIR_ENTRY *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk)))

#define sk_BY_DIR_ENTRY_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk), \
          CHECKED_YCAST(void *, BY_DIR_ENTRY *, p))

#define sk_BY_DIR_ENTRY_pop(sk) \
  ((BY_DIR_ENTRY *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk)))

#define sk_BY_DIR_ENTRY_dup(sk)      \
  ((STACK_OF(BY_DIR_ENTRY) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_ENTRY) *, sk)))

#define sk_BY_DIR_ENTRY_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk))

#define sk_BY_DIR_ENTRY_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_ENTRY) *, sk))

#define sk_BY_DIR_ENTRY_set_cmp_func(sk, comp)                               \
  ((int (*)(const BY_DIR_ENTRY **a, const BY_DIR_ENTRY **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_ENTRY) *, sk),                  \
      CHECKED_YCAST(stack_cmp_func,                                           \
                   int (*)(const BY_DIR_ENTRY **a, const BY_DIR_ENTRY **b),  \
                   comp)))

#define sk_BY_DIR_ENTRY_deep_copy(sk, copy_func, free_func)              \
  ((STACK_OF(BY_DIR_ENTRY) *)sk_deep_copy(                               \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_ENTRY) *, sk),  \
      CHECKED_YCAST(void *(*)(void *), BY_DIR_ENTRY *(*)(BY_DIR_ENTRY *), \
                   copy_func),                                           \
      CHECKED_YCAST(void (*)(void *), void (*)(BY_DIR_ENTRY *), free_func)))

/* BY_DIR_HASH */
#define sk_BY_DIR_HASH_new(comp)                                             \
  ((STACK_OF(BY_DIR_HASH) *)sk_new(CHECKED_YCAST(                             \
      stack_cmp_func, int (*)(const BY_DIR_HASH **a, const BY_DIR_HASH **b), \
      comp)))

#define sk_BY_DIR_HASH_new_null() ((STACK_OF(BY_DIR_HASH) *)sk_new_null())

#define sk_BY_DIR_HASH_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_HASH) *, sk))

#define sk_BY_DIR_HASH_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk));

#define sk_BY_DIR_HASH_value(sk, i) \
  ((BY_DIR_HASH *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_HASH) *, sk), (i)))

#define sk_BY_DIR_HASH_set(sk, i, p)                                          \
  ((BY_DIR_HASH *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), \
                         (i), CHECKED_YCAST(void *, BY_DIR_HASH *, p)))

#define sk_BY_DIR_HASH_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk))

#define sk_BY_DIR_HASH_pop_free(sk, free_func)             \
  sk_pop_free(                                             \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(BY_DIR_HASH *), free_func))

#define sk_BY_DIR_HASH_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), \
            CHECKED_YCAST(void *, BY_DIR_HASH *, p), (where))

#define sk_BY_DIR_HASH_delete(sk, where) \
  ((BY_DIR_HASH *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), (where)))

#define sk_BY_DIR_HASH_delete_ptr(sk, p)                   \
  ((BY_DIR_HASH *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), \
      CHECKED_YCAST(void *, BY_DIR_HASH *, p)))

#define sk_BY_DIR_HASH_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), (out_index), \
          CHECKED_YCAST(void *, BY_DIR_HASH *, p))

#define sk_BY_DIR_HASH_shift(sk) \
  ((BY_DIR_HASH *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk)))

#define sk_BY_DIR_HASH_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk), \
          CHECKED_YCAST(void *, BY_DIR_HASH *, p))

#define sk_BY_DIR_HASH_pop(sk) \
  ((BY_DIR_HASH *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk)))

#define sk_BY_DIR_HASH_dup(sk)      \
  ((STACK_OF(BY_DIR_HASH) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_HASH) *, sk)))

#define sk_BY_DIR_HASH_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk))

#define sk_BY_DIR_HASH_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_HASH) *, sk))

#define sk_BY_DIR_HASH_set_cmp_func(sk, comp)                              \
  ((int (*)(const BY_DIR_HASH **a, const BY_DIR_HASH **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(BY_DIR_HASH) *, sk),                 \
      CHECKED_YCAST(stack_cmp_func,                                         \
                   int (*)(const BY_DIR_HASH **a, const BY_DIR_HASH **b),  \
                   comp)))

#define sk_BY_DIR_HASH_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(BY_DIR_HASH) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(BY_DIR_HASH) *, sk), \
      CHECKED_YCAST(void *(*)(void *), BY_DIR_HASH *(*)(BY_DIR_HASH *), \
                   copy_func),                                         \
      CHECKED_YCAST(void (*)(void *), void (*)(BY_DIR_HASH *), free_func)))

/* CONF_VALUE */
#define sk_CONF_VALUE_new(comp)                                            \
  ((STACK_OF(CONF_VALUE) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const CONF_VALUE **a, const CONF_VALUE **b), \
      comp)))

#define sk_CONF_VALUE_new_null() ((STACK_OF(CONF_VALUE) *)sk_new_null())

#define sk_CONF_VALUE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk));

#define sk_CONF_VALUE_value(sk, i) \
  ((CONF_VALUE *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk), (i)))

#define sk_CONF_VALUE_set(sk, i, p)                                         \
  ((CONF_VALUE *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
                        (i), CHECKED_YCAST(void *, CONF_VALUE *, p)))

#define sk_CONF_VALUE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(CONF_VALUE *), free_func))

#define sk_CONF_VALUE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
            CHECKED_YCAST(void *, CONF_VALUE *, p), (where))

#define sk_CONF_VALUE_delete(sk, where)                                        \
  ((CONF_VALUE *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
                           (where)))

#define sk_CONF_VALUE_delete_ptr(sk, p)                   \
  ((CONF_VALUE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_YCAST(void *, CONF_VALUE *, p)))

#define sk_CONF_VALUE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), (out_index), \
          CHECKED_YCAST(void *, CONF_VALUE *, p))

#define sk_CONF_VALUE_shift(sk) \
  ((CONF_VALUE *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
          CHECKED_YCAST(void *, CONF_VALUE *, p))

#define sk_CONF_VALUE_pop(sk) \
  ((CONF_VALUE *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_dup(sk)      \
  ((STACK_OF(CONF_VALUE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_set_cmp_func(sk, comp)                             \
  ((int (*)(const CONF_VALUE **a, const CONF_VALUE **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(CONF_VALUE) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const CONF_VALUE **a, const CONF_VALUE **b),  \
                   comp)))

#define sk_CONF_VALUE_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(CONF_VALUE) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_YCAST(void *(*)(void *), CONF_VALUE *(*)(CONF_VALUE *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(CONF_VALUE *), free_func)))

/* CRYPTO_BUFFER */
#define sk_CRYPTO_BUFFER_new(comp)                 \
  ((STACK_OF(CRYPTO_BUFFER) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                              \
      int (*)(const CRYPTO_BUFFER **a, const CRYPTO_BUFFER **b), comp)))

#define sk_CRYPTO_BUFFER_new_null() ((STACK_OF(CRYPTO_BUFFER) *)sk_new_null())

#define sk_CRYPTO_BUFFER_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_BUFFER) *, sk))

#define sk_CRYPTO_BUFFER_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk));

#define sk_CRYPTO_BUFFER_value(sk, i) \
  ((CRYPTO_BUFFER *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_BUFFER) *, sk), (i)))

#define sk_CRYPTO_BUFFER_set(sk, i, p)                            \
  ((CRYPTO_BUFFER *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), (i), \
      CHECKED_YCAST(void *, CRYPTO_BUFFER *, p)))

#define sk_CRYPTO_BUFFER_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk))

#define sk_CRYPTO_BUFFER_pop_free(sk, free_func)             \
  sk_pop_free(                                               \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(CRYPTO_BUFFER *), free_func))

#define sk_CRYPTO_BUFFER_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), \
            CHECKED_YCAST(void *, CRYPTO_BUFFER *, p), (where))

#define sk_CRYPTO_BUFFER_delete(sk, where) \
  ((CRYPTO_BUFFER *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), (where)))

#define sk_CRYPTO_BUFFER_delete_ptr(sk, p)                   \
  ((CRYPTO_BUFFER *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), \
      CHECKED_YCAST(void *, CRYPTO_BUFFER *, p)))

#define sk_CRYPTO_BUFFER_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), (out_index), \
          CHECKED_YCAST(void *, CRYPTO_BUFFER *, p))

#define sk_CRYPTO_BUFFER_shift(sk) \
  ((CRYPTO_BUFFER *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk)))

#define sk_CRYPTO_BUFFER_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk), \
          CHECKED_YCAST(void *, CRYPTO_BUFFER *, p))

#define sk_CRYPTO_BUFFER_pop(sk) \
  ((CRYPTO_BUFFER *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk)))

#define sk_CRYPTO_BUFFER_dup(sk)      \
  ((STACK_OF(CRYPTO_BUFFER) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_BUFFER) *, sk)))

#define sk_CRYPTO_BUFFER_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk))

#define sk_CRYPTO_BUFFER_is_sorted(sk) \
  sk_is_sorted(                        \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_BUFFER) *, sk))

#define sk_CRYPTO_BUFFER_set_cmp_func(sk, comp)                                \
  ((int (*)(const CRYPTO_BUFFER **a, const CRYPTO_BUFFER **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_BUFFER) *, sk),                   \
      CHECKED_YCAST(stack_cmp_func,                                             \
                   int (*)(const CRYPTO_BUFFER **a, const CRYPTO_BUFFER **b),  \
                   comp)))

#define sk_CRYPTO_BUFFER_deep_copy(sk, copy_func, free_func)               \
  ((STACK_OF(CRYPTO_BUFFER) *)sk_deep_copy(                                \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_BUFFER) *, sk),   \
      CHECKED_YCAST(void *(*)(void *), CRYPTO_BUFFER *(*)(CRYPTO_BUFFER *), \
                   copy_func),                                             \
      CHECKED_YCAST(void (*)(void *), void (*)(CRYPTO_BUFFER *), free_func)))

/* CRYPTO_EX_DATA_FUNCS */
#define sk_CRYPTO_EX_DATA_FUNCS_new(comp)                                      \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_new(CHECKED_YCAST(                      \
      stack_cmp_func,                                                          \
      int (*)(const CRYPTO_EX_DATA_FUNCS **a, const CRYPTO_EX_DATA_FUNCS **b), \
      comp)))

#define sk_CRYPTO_EX_DATA_FUNCS_new_null() \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_new_null())

#define sk_CRYPTO_EX_DATA_FUNCS_num(sk)                                       \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, \
                      sk))

#define sk_CRYPTO_EX_DATA_FUNCS_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk));

#define sk_CRYPTO_EX_DATA_FUNCS_value(sk, i)                               \
  ((CRYPTO_EX_DATA_FUNCS *)sk_value(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, \
                   sk),                                                    \
      (i)))

#define sk_CRYPTO_EX_DATA_FUNCS_set(sk, i, p)                            \
  ((CRYPTO_EX_DATA_FUNCS *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), (i), \
      CHECKED_YCAST(void *, CRYPTO_EX_DATA_FUNCS *, p)))

#define sk_CRYPTO_EX_DATA_FUNCS_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(CRYPTO_EX_DATA_FUNCS *), \
                           free_func))

#define sk_CRYPTO_EX_DATA_FUNCS_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
            CHECKED_YCAST(void *, CRYPTO_EX_DATA_FUNCS *, p), (where))

#define sk_CRYPTO_EX_DATA_FUNCS_delete(sk, where) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), (where)))

#define sk_CRYPTO_EX_DATA_FUNCS_delete_ptr(sk, p)                   \
  ((CRYPTO_EX_DATA_FUNCS *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
      CHECKED_YCAST(void *, CRYPTO_EX_DATA_FUNCS *, p)))

#define sk_CRYPTO_EX_DATA_FUNCS_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
          (out_index), CHECKED_YCAST(void *, CRYPTO_EX_DATA_FUNCS *, p))

#define sk_CRYPTO_EX_DATA_FUNCS_shift(sk) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
          CHECKED_YCAST(void *, CRYPTO_EX_DATA_FUNCS *, p))

#define sk_CRYPTO_EX_DATA_FUNCS_pop(sk) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_dup(sk)                   \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_dup(CHECKED_YCAST( \
      const _STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *,   \
                            const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func(sk, comp)                       \
  ((int (*)(const CRYPTO_EX_DATA_FUNCS **a, const CRYPTO_EX_DATA_FUNCS **b)) \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk),     \
           CHECKED_YCAST(stack_cmp_func,                                      \
                        int (*)(const CRYPTO_EX_DATA_FUNCS **a,              \
                                const CRYPTO_EX_DATA_FUNCS **b),             \
                        comp)))

#define sk_CRYPTO_EX_DATA_FUNCS_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_deep_copy(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, \
                   sk),                                                    \
      CHECKED_YCAST(void *(*)(void *),                                      \
                   CRYPTO_EX_DATA_FUNCS *(*)(CRYPTO_EX_DATA_FUNCS *),      \
                   copy_func),                                             \
      CHECKED_YCAST(void (*)(void *), void (*)(CRYPTO_EX_DATA_FUNCS *),     \
                   free_func)))

/* DIST_POINT */
#define sk_DIST_POINT_new(comp)                                            \
  ((STACK_OF(DIST_POINT) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const DIST_POINT **a, const DIST_POINT **b), \
      comp)))

#define sk_DIST_POINT_new_null() ((STACK_OF(DIST_POINT) *)sk_new_null())

#define sk_DIST_POINT_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(DIST_POINT) *, sk))

#define sk_DIST_POINT_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk));

#define sk_DIST_POINT_value(sk, i) \
  ((DIST_POINT *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(DIST_POINT) *, sk), (i)))

#define sk_DIST_POINT_set(sk, i, p)                                         \
  ((DIST_POINT *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
                        (i), CHECKED_YCAST(void *, DIST_POINT *, p)))

#define sk_DIST_POINT_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk))

#define sk_DIST_POINT_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(DIST_POINT *), free_func))

#define sk_DIST_POINT_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
            CHECKED_YCAST(void *, DIST_POINT *, p), (where))

#define sk_DIST_POINT_delete(sk, where)                                        \
  ((DIST_POINT *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
                           (where)))

#define sk_DIST_POINT_delete_ptr(sk, p)                   \
  ((DIST_POINT *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
      CHECKED_YCAST(void *, DIST_POINT *, p)))

#define sk_DIST_POINT_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), (out_index), \
          CHECKED_YCAST(void *, DIST_POINT *, p))

#define sk_DIST_POINT_shift(sk) \
  ((DIST_POINT *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk)))

#define sk_DIST_POINT_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk), \
          CHECKED_YCAST(void *, DIST_POINT *, p))

#define sk_DIST_POINT_pop(sk) \
  ((DIST_POINT *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk)))

#define sk_DIST_POINT_dup(sk)      \
  ((STACK_OF(DIST_POINT) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(DIST_POINT) *, sk)))

#define sk_DIST_POINT_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk))

#define sk_DIST_POINT_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(DIST_POINT) *, sk))

#define sk_DIST_POINT_set_cmp_func(sk, comp)                             \
  ((int (*)(const DIST_POINT **a, const DIST_POINT **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(DIST_POINT) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const DIST_POINT **a, const DIST_POINT **b),  \
                   comp)))

#define sk_DIST_POINT_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(DIST_POINT) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(DIST_POINT) *, sk), \
      CHECKED_YCAST(void *(*)(void *), DIST_POINT *(*)(DIST_POINT *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(DIST_POINT *), free_func)))

/* GENERAL_NAME */
#define sk_GENERAL_NAME_new(comp)                                              \
  ((STACK_OF(GENERAL_NAME) *)sk_new(CHECKED_YCAST(                              \
      stack_cmp_func, int (*)(const GENERAL_NAME **a, const GENERAL_NAME **b), \
      comp)))

#define sk_GENERAL_NAME_new_null() ((STACK_OF(GENERAL_NAME) *)sk_new_null())

#define sk_GENERAL_NAME_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAME) *, sk))

#define sk_GENERAL_NAME_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk));

#define sk_GENERAL_NAME_value(sk, i) \
  ((GENERAL_NAME *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAME) *, sk), (i)))

#define sk_GENERAL_NAME_set(sk, i, p)                            \
  ((GENERAL_NAME *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), (i), \
      CHECKED_YCAST(void *, GENERAL_NAME *, p)))

#define sk_GENERAL_NAME_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk))

#define sk_GENERAL_NAME_pop_free(sk, free_func)             \
  sk_pop_free(                                              \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_NAME *), free_func))

#define sk_GENERAL_NAME_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), \
            CHECKED_YCAST(void *, GENERAL_NAME *, p), (where))

#define sk_GENERAL_NAME_delete(sk, where) \
  ((GENERAL_NAME *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), (where)))

#define sk_GENERAL_NAME_delete_ptr(sk, p)                   \
  ((GENERAL_NAME *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), \
      CHECKED_YCAST(void *, GENERAL_NAME *, p)))

#define sk_GENERAL_NAME_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), (out_index), \
          CHECKED_YCAST(void *, GENERAL_NAME *, p))

#define sk_GENERAL_NAME_shift(sk) \
  ((GENERAL_NAME *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk)))

#define sk_GENERAL_NAME_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk), \
          CHECKED_YCAST(void *, GENERAL_NAME *, p))

#define sk_GENERAL_NAME_pop(sk) \
  ((GENERAL_NAME *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk)))

#define sk_GENERAL_NAME_dup(sk)      \
  ((STACK_OF(GENERAL_NAME) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAME) *, sk)))

#define sk_GENERAL_NAME_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk))

#define sk_GENERAL_NAME_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAME) *, sk))

#define sk_GENERAL_NAME_set_cmp_func(sk, comp)                               \
  ((int (*)(const GENERAL_NAME **a, const GENERAL_NAME **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAME) *, sk),                  \
      CHECKED_YCAST(stack_cmp_func,                                           \
                   int (*)(const GENERAL_NAME **a, const GENERAL_NAME **b),  \
                   comp)))

#define sk_GENERAL_NAME_deep_copy(sk, copy_func, free_func)              \
  ((STACK_OF(GENERAL_NAME) *)sk_deep_copy(                               \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAME) *, sk),  \
      CHECKED_YCAST(void *(*)(void *), GENERAL_NAME *(*)(GENERAL_NAME *), \
                   copy_func),                                           \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_NAME *), free_func)))

/* GENERAL_NAMES */
#define sk_GENERAL_NAMES_new(comp)                 \
  ((STACK_OF(GENERAL_NAMES) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                              \
      int (*)(const GENERAL_NAMES **a, const GENERAL_NAMES **b), comp)))

#define sk_GENERAL_NAMES_new_null() ((STACK_OF(GENERAL_NAMES) *)sk_new_null())

#define sk_GENERAL_NAMES_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAMES) *, sk))

#define sk_GENERAL_NAMES_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk));

#define sk_GENERAL_NAMES_value(sk, i) \
  ((GENERAL_NAMES *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAMES) *, sk), (i)))

#define sk_GENERAL_NAMES_set(sk, i, p)                            \
  ((GENERAL_NAMES *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), (i), \
      CHECKED_YCAST(void *, GENERAL_NAMES *, p)))

#define sk_GENERAL_NAMES_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk))

#define sk_GENERAL_NAMES_pop_free(sk, free_func)             \
  sk_pop_free(                                               \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_NAMES *), free_func))

#define sk_GENERAL_NAMES_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), \
            CHECKED_YCAST(void *, GENERAL_NAMES *, p), (where))

#define sk_GENERAL_NAMES_delete(sk, where) \
  ((GENERAL_NAMES *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), (where)))

#define sk_GENERAL_NAMES_delete_ptr(sk, p)                   \
  ((GENERAL_NAMES *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), \
      CHECKED_YCAST(void *, GENERAL_NAMES *, p)))

#define sk_GENERAL_NAMES_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), (out_index), \
          CHECKED_YCAST(void *, GENERAL_NAMES *, p))

#define sk_GENERAL_NAMES_shift(sk) \
  ((GENERAL_NAMES *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk)))

#define sk_GENERAL_NAMES_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk), \
          CHECKED_YCAST(void *, GENERAL_NAMES *, p))

#define sk_GENERAL_NAMES_pop(sk) \
  ((GENERAL_NAMES *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk)))

#define sk_GENERAL_NAMES_dup(sk)      \
  ((STACK_OF(GENERAL_NAMES) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAMES) *, sk)))

#define sk_GENERAL_NAMES_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk))

#define sk_GENERAL_NAMES_is_sorted(sk) \
  sk_is_sorted(                        \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAMES) *, sk))

#define sk_GENERAL_NAMES_set_cmp_func(sk, comp)                                \
  ((int (*)(const GENERAL_NAMES **a, const GENERAL_NAMES **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_NAMES) *, sk),                   \
      CHECKED_YCAST(stack_cmp_func,                                             \
                   int (*)(const GENERAL_NAMES **a, const GENERAL_NAMES **b),  \
                   comp)))

#define sk_GENERAL_NAMES_deep_copy(sk, copy_func, free_func)               \
  ((STACK_OF(GENERAL_NAMES) *)sk_deep_copy(                                \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_NAMES) *, sk),   \
      CHECKED_YCAST(void *(*)(void *), GENERAL_NAMES *(*)(GENERAL_NAMES *), \
                   copy_func),                                             \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_NAMES *), free_func)))

/* GENERAL_SUBTREE */
#define sk_GENERAL_SUBTREE_new(comp)                 \
  ((STACK_OF(GENERAL_SUBTREE) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                                \
      int (*)(const GENERAL_SUBTREE **a, const GENERAL_SUBTREE **b), comp)))

#define sk_GENERAL_SUBTREE_new_null() \
  ((STACK_OF(GENERAL_SUBTREE) *)sk_new_null())

#define sk_GENERAL_SUBTREE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_SUBTREE) *, sk))

#define sk_GENERAL_SUBTREE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk));

#define sk_GENERAL_SUBTREE_value(sk, i)                                    \
  ((GENERAL_SUBTREE *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_SUBTREE) *, sk), \
      (i)))

#define sk_GENERAL_SUBTREE_set(sk, i, p)                            \
  ((GENERAL_SUBTREE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), (i), \
      CHECKED_YCAST(void *, GENERAL_SUBTREE *, p)))

#define sk_GENERAL_SUBTREE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk))

#define sk_GENERAL_SUBTREE_pop_free(sk, free_func)             \
  sk_pop_free(                                                 \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_SUBTREE *), free_func))

#define sk_GENERAL_SUBTREE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), \
            CHECKED_YCAST(void *, GENERAL_SUBTREE *, p), (where))

#define sk_GENERAL_SUBTREE_delete(sk, where) \
  ((GENERAL_SUBTREE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), (where)))

#define sk_GENERAL_SUBTREE_delete_ptr(sk, p)                   \
  ((GENERAL_SUBTREE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), \
      CHECKED_YCAST(void *, GENERAL_SUBTREE *, p)))

#define sk_GENERAL_SUBTREE_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), \
          (out_index), CHECKED_YCAST(void *, GENERAL_SUBTREE *, p))

#define sk_GENERAL_SUBTREE_shift(sk) \
  ((GENERAL_SUBTREE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk)))

#define sk_GENERAL_SUBTREE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk), \
          CHECKED_YCAST(void *, GENERAL_SUBTREE *, p))

#define sk_GENERAL_SUBTREE_pop(sk) \
  ((GENERAL_SUBTREE *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk)))

#define sk_GENERAL_SUBTREE_dup(sk)      \
  ((STACK_OF(GENERAL_SUBTREE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_SUBTREE) *, sk)))

#define sk_GENERAL_SUBTREE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk))

#define sk_GENERAL_SUBTREE_is_sorted(sk) \
  sk_is_sorted(                          \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_SUBTREE) *, sk))

#define sk_GENERAL_SUBTREE_set_cmp_func(sk, comp)                           \
  ((int (*)(const GENERAL_SUBTREE **a, const GENERAL_SUBTREE **b))          \
       sk_set_cmp_func(                                                     \
           CHECKED_YCAST(_STACK *, STACK_OF(GENERAL_SUBTREE) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const GENERAL_SUBTREE **a,  \
                                                const GENERAL_SUBTREE **b), \
                        comp)))

#define sk_GENERAL_SUBTREE_deep_copy(sk, copy_func, free_func)                 \
  ((STACK_OF(GENERAL_SUBTREE) *)sk_deep_copy(                                  \
      CHECKED_YCAST(const _STACK *, const STACK_OF(GENERAL_SUBTREE) *, sk),     \
      CHECKED_YCAST(void *(*)(void *), GENERAL_SUBTREE *(*)(GENERAL_SUBTREE *), \
                   copy_func),                                                 \
      CHECKED_YCAST(void (*)(void *), void (*)(GENERAL_SUBTREE *), free_func)))

/* POLICYINFO */
#define sk_POLICYINFO_new(comp)                                            \
  ((STACK_OF(POLICYINFO) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const POLICYINFO **a, const POLICYINFO **b), \
      comp)))

#define sk_POLICYINFO_new_null() ((STACK_OF(POLICYINFO) *)sk_new_null())

#define sk_POLICYINFO_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYINFO) *, sk))

#define sk_POLICYINFO_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk));

#define sk_POLICYINFO_value(sk, i) \
  ((POLICYINFO *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYINFO) *, sk), (i)))

#define sk_POLICYINFO_set(sk, i, p)                                         \
  ((POLICYINFO *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
                        (i), CHECKED_YCAST(void *, POLICYINFO *, p)))

#define sk_POLICYINFO_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk))

#define sk_POLICYINFO_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICYINFO *), free_func))

#define sk_POLICYINFO_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
            CHECKED_YCAST(void *, POLICYINFO *, p), (where))

#define sk_POLICYINFO_delete(sk, where)                                        \
  ((POLICYINFO *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
                           (where)))

#define sk_POLICYINFO_delete_ptr(sk, p)                   \
  ((POLICYINFO *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
      CHECKED_YCAST(void *, POLICYINFO *, p)))

#define sk_POLICYINFO_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), (out_index), \
          CHECKED_YCAST(void *, POLICYINFO *, p))

#define sk_POLICYINFO_shift(sk) \
  ((POLICYINFO *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk)))

#define sk_POLICYINFO_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk), \
          CHECKED_YCAST(void *, POLICYINFO *, p))

#define sk_POLICYINFO_pop(sk) \
  ((POLICYINFO *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk)))

#define sk_POLICYINFO_dup(sk)      \
  ((STACK_OF(POLICYINFO) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYINFO) *, sk)))

#define sk_POLICYINFO_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk))

#define sk_POLICYINFO_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYINFO) *, sk))

#define sk_POLICYINFO_set_cmp_func(sk, comp)                             \
  ((int (*)(const POLICYINFO **a, const POLICYINFO **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYINFO) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const POLICYINFO **a, const POLICYINFO **b),  \
                   comp)))

#define sk_POLICYINFO_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(POLICYINFO) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYINFO) *, sk), \
      CHECKED_YCAST(void *(*)(void *), POLICYINFO *(*)(POLICYINFO *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICYINFO *), free_func)))

/* POLICYQUALINFO */
#define sk_POLICYQUALINFO_new(comp)                 \
  ((STACK_OF(POLICYQUALINFO) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const POLICYQUALINFO **a, const POLICYQUALINFO **b), comp)))

#define sk_POLICYQUALINFO_new_null() ((STACK_OF(POLICYQUALINFO) *)sk_new_null())

#define sk_POLICYQUALINFO_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYQUALINFO) *, sk))

#define sk_POLICYQUALINFO_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk));

#define sk_POLICYQUALINFO_value(sk, i)                                    \
  ((POLICYQUALINFO *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYQUALINFO) *, sk), \
      (i)))

#define sk_POLICYQUALINFO_set(sk, i, p)                            \
  ((POLICYQUALINFO *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), (i), \
      CHECKED_YCAST(void *, POLICYQUALINFO *, p)))

#define sk_POLICYQUALINFO_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk))

#define sk_POLICYQUALINFO_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICYQUALINFO *), free_func))

#define sk_POLICYQUALINFO_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), \
            CHECKED_YCAST(void *, POLICYQUALINFO *, p), (where))

#define sk_POLICYQUALINFO_delete(sk, where) \
  ((POLICYQUALINFO *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), (where)))

#define sk_POLICYQUALINFO_delete_ptr(sk, p)                   \
  ((POLICYQUALINFO *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), \
      CHECKED_YCAST(void *, POLICYQUALINFO *, p)))

#define sk_POLICYQUALINFO_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), (out_index), \
          CHECKED_YCAST(void *, POLICYQUALINFO *, p))

#define sk_POLICYQUALINFO_shift(sk) \
  ((POLICYQUALINFO *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk)))

#define sk_POLICYQUALINFO_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk), \
          CHECKED_YCAST(void *, POLICYQUALINFO *, p))

#define sk_POLICYQUALINFO_pop(sk) \
  ((POLICYQUALINFO *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk)))

#define sk_POLICYQUALINFO_dup(sk)      \
  ((STACK_OF(POLICYQUALINFO) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYQUALINFO) *, sk)))

#define sk_POLICYQUALINFO_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk))

#define sk_POLICYQUALINFO_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYQUALINFO) *, sk))

#define sk_POLICYQUALINFO_set_cmp_func(sk, comp)                           \
  ((int (*)(const POLICYQUALINFO **a, const POLICYQUALINFO **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(POLICYQUALINFO) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const POLICYQUALINFO **a,  \
                                                const POLICYQUALINFO **b), \
                        comp)))

#define sk_POLICYQUALINFO_deep_copy(sk, copy_func, free_func)                \
  ((STACK_OF(POLICYQUALINFO) *)sk_deep_copy(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICYQUALINFO) *, sk),    \
      CHECKED_YCAST(void *(*)(void *), POLICYQUALINFO *(*)(POLICYQUALINFO *), \
                   copy_func),                                               \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICYQUALINFO *), free_func)))

/* POLICY_MAPPING */
#define sk_POLICY_MAPPING_new(comp)                 \
  ((STACK_OF(POLICY_MAPPING) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const POLICY_MAPPING **a, const POLICY_MAPPING **b), comp)))

#define sk_POLICY_MAPPING_new_null() ((STACK_OF(POLICY_MAPPING) *)sk_new_null())

#define sk_POLICY_MAPPING_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(POLICY_MAPPING) *, sk))

#define sk_POLICY_MAPPING_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk));

#define sk_POLICY_MAPPING_value(sk, i)                                    \
  ((POLICY_MAPPING *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICY_MAPPING) *, sk), \
      (i)))

#define sk_POLICY_MAPPING_set(sk, i, p)                            \
  ((POLICY_MAPPING *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), (i), \
      CHECKED_YCAST(void *, POLICY_MAPPING *, p)))

#define sk_POLICY_MAPPING_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk))

#define sk_POLICY_MAPPING_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICY_MAPPING *), free_func))

#define sk_POLICY_MAPPING_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), \
            CHECKED_YCAST(void *, POLICY_MAPPING *, p), (where))

#define sk_POLICY_MAPPING_delete(sk, where) \
  ((POLICY_MAPPING *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), (where)))

#define sk_POLICY_MAPPING_delete_ptr(sk, p)                   \
  ((POLICY_MAPPING *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), \
      CHECKED_YCAST(void *, POLICY_MAPPING *, p)))

#define sk_POLICY_MAPPING_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), (out_index), \
          CHECKED_YCAST(void *, POLICY_MAPPING *, p))

#define sk_POLICY_MAPPING_shift(sk) \
  ((POLICY_MAPPING *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk)))

#define sk_POLICY_MAPPING_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk), \
          CHECKED_YCAST(void *, POLICY_MAPPING *, p))

#define sk_POLICY_MAPPING_pop(sk) \
  ((POLICY_MAPPING *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk)))

#define sk_POLICY_MAPPING_dup(sk)      \
  ((STACK_OF(POLICY_MAPPING) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICY_MAPPING) *, sk)))

#define sk_POLICY_MAPPING_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk))

#define sk_POLICY_MAPPING_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICY_MAPPING) *, sk))

#define sk_POLICY_MAPPING_set_cmp_func(sk, comp)                           \
  ((int (*)(const POLICY_MAPPING **a, const POLICY_MAPPING **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(POLICY_MAPPING) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const POLICY_MAPPING **a,  \
                                                const POLICY_MAPPING **b), \
                        comp)))

#define sk_POLICY_MAPPING_deep_copy(sk, copy_func, free_func)                \
  ((STACK_OF(POLICY_MAPPING) *)sk_deep_copy(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(POLICY_MAPPING) *, sk),    \
      CHECKED_YCAST(void *(*)(void *), POLICY_MAPPING *(*)(POLICY_MAPPING *), \
                   copy_func),                                               \
      CHECKED_YCAST(void (*)(void *), void (*)(POLICY_MAPPING *), free_func)))

/* YRSA_additional_prime */
#define sk_YRSA_additional_prime_new(comp)                                      \
  ((STACK_OF(YRSA_additional_prime) *)sk_new(CHECKED_YCAST(                      \
      stack_cmp_func,                                                          \
      int (*)(const YRSA_additional_prime **a, const YRSA_additional_prime **b), \
      comp)))

#define sk_YRSA_additional_prime_new_null() \
  ((STACK_OF(YRSA_additional_prime) *)sk_new_null())

#define sk_YRSA_additional_prime_num(sk)                                       \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YRSA_additional_prime) *, \
                      sk))

#define sk_YRSA_additional_prime_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk));

#define sk_YRSA_additional_prime_value(sk, i)                               \
  ((YRSA_additional_prime *)sk_value(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YRSA_additional_prime) *, \
                   sk),                                                    \
      (i)))

#define sk_YRSA_additional_prime_set(sk, i, p)                            \
  ((YRSA_additional_prime *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), (i), \
      CHECKED_YCAST(void *, YRSA_additional_prime *, p)))

#define sk_YRSA_additional_prime_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk))

#define sk_YRSA_additional_prime_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(YRSA_additional_prime *), \
                           free_func))

#define sk_YRSA_additional_prime_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), \
            CHECKED_YCAST(void *, YRSA_additional_prime *, p), (where))

#define sk_YRSA_additional_prime_delete(sk, where) \
  ((YRSA_additional_prime *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), (where)))

#define sk_YRSA_additional_prime_delete_ptr(sk, p)                   \
  ((YRSA_additional_prime *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), \
      CHECKED_YCAST(void *, YRSA_additional_prime *, p)))

#define sk_YRSA_additional_prime_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), \
          (out_index), CHECKED_YCAST(void *, YRSA_additional_prime *, p))

#define sk_YRSA_additional_prime_shift(sk) \
  ((YRSA_additional_prime *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk)))

#define sk_YRSA_additional_prime_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk), \
          CHECKED_YCAST(void *, YRSA_additional_prime *, p))

#define sk_YRSA_additional_prime_pop(sk) \
  ((YRSA_additional_prime *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk)))

#define sk_YRSA_additional_prime_dup(sk)                   \
  ((STACK_OF(YRSA_additional_prime) *)sk_dup(CHECKED_YCAST( \
      const _STACK *, const STACK_OF(YRSA_additional_prime) *, sk)))

#define sk_YRSA_additional_prime_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk))

#define sk_YRSA_additional_prime_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *,   \
                            const STACK_OF(YRSA_additional_prime) *, sk))

#define sk_YRSA_additional_prime_set_cmp_func(sk, comp)                       \
  ((int (*)(const YRSA_additional_prime **a, const YRSA_additional_prime **b)) \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(YRSA_additional_prime) *, sk),     \
           CHECKED_YCAST(stack_cmp_func,                                      \
                        int (*)(const YRSA_additional_prime **a,              \
                                const YRSA_additional_prime **b),             \
                        comp)))

#define sk_YRSA_additional_prime_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(YRSA_additional_prime) *)sk_deep_copy(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YRSA_additional_prime) *, \
                   sk),                                                    \
      CHECKED_YCAST(void *(*)(void *),                                      \
                   YRSA_additional_prime *(*)(YRSA_additional_prime *),      \
                   copy_func),                                             \
      CHECKED_YCAST(void (*)(void *), void (*)(YRSA_additional_prime *),     \
                   free_func)))

/* SSL_COMP */
#define sk_SSL_COMP_new(comp)                 \
  ((STACK_OF(SSL_COMP) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const SSL_COMP **a, const SSL_COMP **b), comp)))

#define sk_SSL_COMP_new_null() ((STACK_OF(SSL_COMP) *)sk_new_null())

#define sk_SSL_COMP_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_COMP) *, sk))

#define sk_SSL_COMP_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk));

#define sk_SSL_COMP_value(sk, i) \
  ((SSL_COMP *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_COMP) *, sk), (i)))

#define sk_SSL_COMP_set(sk, i, p)                                            \
  ((SSL_COMP *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), (i), \
                      CHECKED_YCAST(void *, SSL_COMP *, p)))

#define sk_SSL_COMP_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk))

#define sk_SSL_COMP_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(SSL_COMP *), free_func))

#define sk_SSL_COMP_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), \
            CHECKED_YCAST(void *, SSL_COMP *, p), (where))

#define sk_SSL_COMP_delete(sk, where)                                      \
  ((SSL_COMP *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), \
                         (where)))

#define sk_SSL_COMP_delete_ptr(sk, p)                                          \
  ((SSL_COMP *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), \
                             CHECKED_YCAST(void *, SSL_COMP *, p)))

#define sk_SSL_COMP_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), (out_index), \
          CHECKED_YCAST(void *, SSL_COMP *, p))

#define sk_SSL_COMP_shift(sk) \
  ((SSL_COMP *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk)))

#define sk_SSL_COMP_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk), \
          CHECKED_YCAST(void *, SSL_COMP *, p))

#define sk_SSL_COMP_pop(sk) \
  ((SSL_COMP *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk)))

#define sk_SSL_COMP_dup(sk)      \
  ((STACK_OF(SSL_COMP) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_COMP) *, sk)))

#define sk_SSL_COMP_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk))

#define sk_SSL_COMP_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_COMP) *, sk))

#define sk_SSL_COMP_set_cmp_func(sk, comp)                           \
  ((int (*)(const SSL_COMP **a, const SSL_COMP **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_COMP) *, sk),              \
      CHECKED_YCAST(stack_cmp_func,                                   \
                   int (*)(const SSL_COMP **a, const SSL_COMP **b), comp)))

#define sk_SSL_COMP_deep_copy(sk, copy_func, free_func)                      \
  ((STACK_OF(SSL_COMP) *)sk_deep_copy(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_COMP) *, sk),          \
      CHECKED_YCAST(void *(*)(void *), SSL_COMP *(*)(SSL_COMP *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(SSL_COMP *), free_func)))

/* SSL_CUSTOM_EXTENSION */
#define sk_SSL_CUSTOM_EXTENSION_new(comp)                                      \
  ((STACK_OF(SSL_CUSTOM_EXTENSION) *)sk_new(CHECKED_YCAST(                      \
      stack_cmp_func,                                                          \
      int (*)(const SSL_CUSTOM_EXTENSION **a, const SSL_CUSTOM_EXTENSION **b), \
      comp)))

#define sk_SSL_CUSTOM_EXTENSION_new_null() \
  ((STACK_OF(SSL_CUSTOM_EXTENSION) *)sk_new_null())

#define sk_SSL_CUSTOM_EXTENSION_num(sk)                                       \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CUSTOM_EXTENSION) *, \
                      sk))

#define sk_SSL_CUSTOM_EXTENSION_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk));

#define sk_SSL_CUSTOM_EXTENSION_value(sk, i)                               \
  ((SSL_CUSTOM_EXTENSION *)sk_value(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CUSTOM_EXTENSION) *, \
                   sk),                                                    \
      (i)))

#define sk_SSL_CUSTOM_EXTENSION_set(sk, i, p)                            \
  ((SSL_CUSTOM_EXTENSION *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), (i), \
      CHECKED_YCAST(void *, SSL_CUSTOM_EXTENSION *, p)))

#define sk_SSL_CUSTOM_EXTENSION_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk))

#define sk_SSL_CUSTOM_EXTENSION_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(SSL_CUSTOM_EXTENSION *), \
                           free_func))

#define sk_SSL_CUSTOM_EXTENSION_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), \
            CHECKED_YCAST(void *, SSL_CUSTOM_EXTENSION *, p), (where))

#define sk_SSL_CUSTOM_EXTENSION_delete(sk, where) \
  ((SSL_CUSTOM_EXTENSION *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), (where)))

#define sk_SSL_CUSTOM_EXTENSION_delete_ptr(sk, p)                   \
  ((SSL_CUSTOM_EXTENSION *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), \
      CHECKED_YCAST(void *, SSL_CUSTOM_EXTENSION *, p)))

#define sk_SSL_CUSTOM_EXTENSION_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), \
          (out_index), CHECKED_YCAST(void *, SSL_CUSTOM_EXTENSION *, p))

#define sk_SSL_CUSTOM_EXTENSION_shift(sk) \
  ((SSL_CUSTOM_EXTENSION *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk)))

#define sk_SSL_CUSTOM_EXTENSION_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk), \
          CHECKED_YCAST(void *, SSL_CUSTOM_EXTENSION *, p))

#define sk_SSL_CUSTOM_EXTENSION_pop(sk) \
  ((SSL_CUSTOM_EXTENSION *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk)))

#define sk_SSL_CUSTOM_EXTENSION_dup(sk)                   \
  ((STACK_OF(SSL_CUSTOM_EXTENSION) *)sk_dup(CHECKED_YCAST( \
      const _STACK *, const STACK_OF(SSL_CUSTOM_EXTENSION) *, sk)))

#define sk_SSL_CUSTOM_EXTENSION_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk))

#define sk_SSL_CUSTOM_EXTENSION_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *,   \
                            const STACK_OF(SSL_CUSTOM_EXTENSION) *, sk))

#define sk_SSL_CUSTOM_EXTENSION_set_cmp_func(sk, comp)                       \
  ((int (*)(const SSL_CUSTOM_EXTENSION **a, const SSL_CUSTOM_EXTENSION **b)) \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(SSL_CUSTOM_EXTENSION) *, sk),     \
           CHECKED_YCAST(stack_cmp_func,                                      \
                        int (*)(const SSL_CUSTOM_EXTENSION **a,              \
                                const SSL_CUSTOM_EXTENSION **b),             \
                        comp)))

#define sk_SSL_CUSTOM_EXTENSION_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(SSL_CUSTOM_EXTENSION) *)sk_deep_copy(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CUSTOM_EXTENSION) *, \
                   sk),                                                    \
      CHECKED_YCAST(void *(*)(void *),                                      \
                   SSL_CUSTOM_EXTENSION *(*)(SSL_CUSTOM_EXTENSION *),      \
                   copy_func),                                             \
      CHECKED_YCAST(void (*)(void *), void (*)(SSL_CUSTOM_EXTENSION *),     \
                   free_func)))

/* STACK_OF_YX509_NAME_ENTRY */
#define sk_STACK_OF_YX509_NAME_ENTRY_new(comp)                      \
  ((STACK_OF(STACK_OF_YX509_NAME_ENTRY) *)sk_new(CHECKED_YCAST(      \
      stack_cmp_func, int (*)(const STACK_OF_YX509_NAME_ENTRY **a,  \
                              const STACK_OF_YX509_NAME_ENTRY **b), \
      comp)))

#define sk_STACK_OF_YX509_NAME_ENTRY_new_null() \
  ((STACK_OF(STACK_OF_YX509_NAME_ENTRY) *)sk_new_null())

#define sk_STACK_OF_YX509_NAME_ENTRY_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *,       \
                      const STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk))

#define sk_STACK_OF_YX509_NAME_ENTRY_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk));

#define sk_STACK_OF_YX509_NAME_ENTRY_value(sk, i)                               \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_value(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, \
                   sk),                                                        \
      (i)))

#define sk_STACK_OF_YX509_NAME_ENTRY_set(sk, i, p)                            \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), (i), \
      CHECKED_YCAST(void *, STACK_OF_YX509_NAME_ENTRY *, p)))

#define sk_STACK_OF_YX509_NAME_ENTRY_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk))

#define sk_STACK_OF_YX509_NAME_ENTRY_pop_free(sk, free_func)                \
  sk_pop_free(                                                             \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk),    \
      CHECKED_YCAST(void (*)(void *), void (*)(STACK_OF_YX509_NAME_ENTRY *), \
                   free_func))

#define sk_STACK_OF_YX509_NAME_ENTRY_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
            CHECKED_YCAST(void *, STACK_OF_YX509_NAME_ENTRY *, p), (where))

#define sk_STACK_OF_YX509_NAME_ENTRY_delete(sk, where)                   \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_delete(                               \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
      (where)))

#define sk_STACK_OF_YX509_NAME_ENTRY_delete_ptr(sk, p)                   \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
      CHECKED_YCAST(void *, STACK_OF_YX509_NAME_ENTRY *, p)))

#define sk_STACK_OF_YX509_NAME_ENTRY_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
          (out_index), CHECKED_YCAST(void *, STACK_OF_YX509_NAME_ENTRY *, p))

#define sk_STACK_OF_YX509_NAME_ENTRY_shift(sk) \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk)))

#define sk_STACK_OF_YX509_NAME_ENTRY_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
          CHECKED_YCAST(void *, STACK_OF_YX509_NAME_ENTRY *, p))

#define sk_STACK_OF_YX509_NAME_ENTRY_pop(sk) \
  ((STACK_OF_YX509_NAME_ENTRY *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk)))

#define sk_STACK_OF_YX509_NAME_ENTRY_dup(sk)                   \
  ((STACK_OF(STACK_OF_YX509_NAME_ENTRY) *)sk_dup(CHECKED_YCAST( \
      const _STACK *, const STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk)))

#define sk_STACK_OF_YX509_NAME_ENTRY_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk))

#define sk_STACK_OF_YX509_NAME_ENTRY_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *,       \
                            const STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk))

#define sk_STACK_OF_YX509_NAME_ENTRY_set_cmp_func(sk, comp)                   \
  ((int (*)(const STACK_OF_YX509_NAME_ENTRY **a,                              \
            const STACK_OF_YX509_NAME_ENTRY **b))                             \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, sk), \
           CHECKED_YCAST(stack_cmp_func,                                      \
                        int (*)(const STACK_OF_YX509_NAME_ENTRY **a,          \
                                const STACK_OF_YX509_NAME_ENTRY **b),         \
                        comp)))

#define sk_STACK_OF_YX509_NAME_ENTRY_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(STACK_OF_YX509_NAME_ENTRY) *)sk_deep_copy(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(STACK_OF_YX509_NAME_ENTRY) *, \
                   sk),                                                        \
      CHECKED_YCAST(void *(*)(void *),                                          \
                   STACK_OF_YX509_NAME_ENTRY *(*)(STACK_OF_YX509_NAME_ENTRY *),  \
                   copy_func),                                                 \
      CHECKED_YCAST(void (*)(void *), void (*)(STACK_OF_YX509_NAME_ENTRY *),     \
                   free_func)))

/* SXNETID */
#define sk_SXNETID_new(comp)                 \
  ((STACK_OF(SXNETID) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const SXNETID **a, const SXNETID **b), comp)))

#define sk_SXNETID_new_null() ((STACK_OF(SXNETID) *)sk_new_null())

#define sk_SXNETID_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(SXNETID) *, sk))

#define sk_SXNETID_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk));

#define sk_SXNETID_value(sk, i) \
  ((SXNETID *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SXNETID) *, sk), (i)))

#define sk_SXNETID_set(sk, i, p)                                           \
  ((SXNETID *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), (i), \
                     CHECKED_YCAST(void *, SXNETID *, p)))

#define sk_SXNETID_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk))

#define sk_SXNETID_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(SXNETID *), free_func))

#define sk_SXNETID_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), \
            CHECKED_YCAST(void *, SXNETID *, p), (where))

#define sk_SXNETID_delete(sk, where)                                     \
  ((SXNETID *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), \
                        (where)))

#define sk_SXNETID_delete_ptr(sk, p)                                         \
  ((SXNETID *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), \
                            CHECKED_YCAST(void *, SXNETID *, p)))

#define sk_SXNETID_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), (out_index), \
          CHECKED_YCAST(void *, SXNETID *, p))

#define sk_SXNETID_shift(sk) \
  ((SXNETID *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk)))

#define sk_SXNETID_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk), \
          CHECKED_YCAST(void *, SXNETID *, p))

#define sk_SXNETID_pop(sk) \
  ((SXNETID *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk)))

#define sk_SXNETID_dup(sk)      \
  ((STACK_OF(SXNETID) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SXNETID) *, sk)))

#define sk_SXNETID_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk))

#define sk_SXNETID_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(SXNETID) *, sk))

#define sk_SXNETID_set_cmp_func(sk, comp)                          \
  ((int (*)(const SXNETID **a, const SXNETID **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(SXNETID) *, sk),             \
      CHECKED_YCAST(stack_cmp_func,                                 \
                   int (*)(const SXNETID **a, const SXNETID **b), comp)))

#define sk_SXNETID_deep_copy(sk, copy_func, free_func)                     \
  ((STACK_OF(SXNETID) *)sk_deep_copy(                                      \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SXNETID) *, sk),         \
      CHECKED_YCAST(void *(*)(void *), SXNETID *(*)(SXNETID *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(SXNETID *), free_func)))

/* YX509 */
#define sk_YX509_new(comp)                 \
  ((STACK_OF(YX509) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const YX509 **a, const YX509 **b), comp)))

#define sk_YX509_new_null() ((STACK_OF(YX509) *)sk_new_null())

#define sk_YX509_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509) *, sk))

#define sk_YX509_zero(sk) sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk));

#define sk_YX509_value(sk, i)                                                  \
  ((YX509 *)sk_value(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509) *, sk), \
                    (i)))

#define sk_YX509_set(sk, i, p)                                        \
  ((YX509 *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), (i), \
                  CHECKED_YCAST(void *, YX509 *, p)))

#define sk_YX509_free(sk) sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk))

#define sk_YX509_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(YX509 *), free_func))

#define sk_YX509_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), \
            CHECKED_YCAST(void *, YX509 *, p), (where))

#define sk_YX509_delete(sk, where) \
  ((YX509 *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), (where)))

#define sk_YX509_delete_ptr(sk, p)                                      \
  ((YX509 *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), \
                         CHECKED_YCAST(void *, YX509 *, p)))

#define sk_YX509_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509 *, p))

#define sk_YX509_shift(sk) \
  ((YX509 *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk)))

#define sk_YX509_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk), \
          CHECKED_YCAST(void *, YX509 *, p))

#define sk_YX509_pop(sk) \
  ((YX509 *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk)))

#define sk_YX509_dup(sk)      \
  ((STACK_OF(YX509) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509) *, sk)))

#define sk_YX509_sort(sk) sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk))

#define sk_YX509_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509) *, sk))

#define sk_YX509_set_cmp_func(sk, comp)                                      \
  ((int (*)(const YX509 **a, const YX509 **b))sk_set_cmp_func(                \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509) *, sk),                         \
      CHECKED_YCAST(stack_cmp_func, int (*)(const YX509 **a, const YX509 **b), \
                   comp)))

#define sk_YX509_deep_copy(sk, copy_func, free_func)                  \
  ((STACK_OF(YX509) *)sk_deep_copy(                                   \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509) *, sk),      \
      CHECKED_YCAST(void *(*)(void *), YX509 *(*)(YX509 *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509 *), free_func)))

/* YX509V3_EXT_METHOD */
#define sk_YX509V3_EXT_METHOD_new(comp)                                   \
  ((STACK_OF(YX509V3_EXT_METHOD) *)sk_new(CHECKED_YCAST(                   \
      stack_cmp_func,                                                    \
      int (*)(const YX509V3_EXT_METHOD **a, const YX509V3_EXT_METHOD **b), \
      comp)))

#define sk_YX509V3_EXT_METHOD_new_null() \
  ((STACK_OF(YX509V3_EXT_METHOD) *)sk_new_null())

#define sk_YX509V3_EXT_METHOD_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509V3_EXT_METHOD) *, sk))

#define sk_YX509V3_EXT_METHOD_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk));

#define sk_YX509V3_EXT_METHOD_value(sk, i)                                    \
  ((YX509V3_EXT_METHOD *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509V3_EXT_METHOD) *, sk), \
      (i)))

#define sk_YX509V3_EXT_METHOD_set(sk, i, p)                            \
  ((YX509V3_EXT_METHOD *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), (i), \
      CHECKED_YCAST(void *, YX509V3_EXT_METHOD *, p)))

#define sk_YX509V3_EXT_METHOD_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk))

#define sk_YX509V3_EXT_METHOD_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(YX509V3_EXT_METHOD *), \
                           free_func))

#define sk_YX509V3_EXT_METHOD_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), \
            CHECKED_YCAST(void *, YX509V3_EXT_METHOD *, p), (where))

#define sk_YX509V3_EXT_METHOD_delete(sk, where) \
  ((YX509V3_EXT_METHOD *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), (where)))

#define sk_YX509V3_EXT_METHOD_delete_ptr(sk, p)                   \
  ((YX509V3_EXT_METHOD *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), \
      CHECKED_YCAST(void *, YX509V3_EXT_METHOD *, p)))

#define sk_YX509V3_EXT_METHOD_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), \
          (out_index), CHECKED_YCAST(void *, YX509V3_EXT_METHOD *, p))

#define sk_YX509V3_EXT_METHOD_shift(sk) \
  ((YX509V3_EXT_METHOD *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk)))

#define sk_YX509V3_EXT_METHOD_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk), \
          CHECKED_YCAST(void *, YX509V3_EXT_METHOD *, p))

#define sk_YX509V3_EXT_METHOD_pop(sk) \
  ((YX509V3_EXT_METHOD *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk)))

#define sk_YX509V3_EXT_METHOD_dup(sk)      \
  ((STACK_OF(YX509V3_EXT_METHOD) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509V3_EXT_METHOD) *, sk)))

#define sk_YX509V3_EXT_METHOD_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk))

#define sk_YX509V3_EXT_METHOD_is_sorted(sk) \
  sk_is_sorted(                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509V3_EXT_METHOD) *, sk))

#define sk_YX509V3_EXT_METHOD_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509V3_EXT_METHOD **a, const YX509V3_EXT_METHOD **b))        \
       sk_set_cmp_func(                                                       \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509V3_EXT_METHOD) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509V3_EXT_METHOD **a,  \
                                                const YX509V3_EXT_METHOD **b), \
                        comp)))

#define sk_YX509V3_EXT_METHOD_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509V3_EXT_METHOD) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509V3_EXT_METHOD) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                        \
                   YX509V3_EXT_METHOD *(*)(YX509V3_EXT_METHOD *), copy_func),  \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509V3_EXT_METHOD *),          \
                   free_func)))

/* YX509_ALGOR */
#define sk_YX509_ALGOR_new(comp)                                            \
  ((STACK_OF(YX509_ALGOR) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const YX509_ALGOR **a, const YX509_ALGOR **b), \
      comp)))

#define sk_YX509_ALGOR_new_null() ((STACK_OF(YX509_ALGOR) *)sk_new_null())

#define sk_YX509_ALGOR_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ALGOR) *, sk))

#define sk_YX509_ALGOR_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk));

#define sk_YX509_ALGOR_value(sk, i) \
  ((YX509_ALGOR *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ALGOR) *, sk), (i)))

#define sk_YX509_ALGOR_set(sk, i, p)                                         \
  ((YX509_ALGOR *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
                        (i), CHECKED_YCAST(void *, YX509_ALGOR *, p)))

#define sk_YX509_ALGOR_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk))

#define sk_YX509_ALGOR_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_ALGOR *), free_func))

#define sk_YX509_ALGOR_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
            CHECKED_YCAST(void *, YX509_ALGOR *, p), (where))

#define sk_YX509_ALGOR_delete(sk, where)                                        \
  ((YX509_ALGOR *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
                           (where)))

#define sk_YX509_ALGOR_delete_ptr(sk, p)                   \
  ((YX509_ALGOR *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
      CHECKED_YCAST(void *, YX509_ALGOR *, p)))

#define sk_YX509_ALGOR_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_ALGOR *, p))

#define sk_YX509_ALGOR_shift(sk) \
  ((YX509_ALGOR *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk)))

#define sk_YX509_ALGOR_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk), \
          CHECKED_YCAST(void *, YX509_ALGOR *, p))

#define sk_YX509_ALGOR_pop(sk) \
  ((YX509_ALGOR *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk)))

#define sk_YX509_ALGOR_dup(sk)      \
  ((STACK_OF(YX509_ALGOR) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ALGOR) *, sk)))

#define sk_YX509_ALGOR_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk))

#define sk_YX509_ALGOR_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ALGOR) *, sk))

#define sk_YX509_ALGOR_set_cmp_func(sk, comp)                             \
  ((int (*)(const YX509_ALGOR **a, const YX509_ALGOR **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ALGOR) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const YX509_ALGOR **a, const YX509_ALGOR **b),  \
                   comp)))

#define sk_YX509_ALGOR_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_ALGOR) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ALGOR) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YX509_ALGOR *(*)(YX509_ALGOR *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_ALGOR *), free_func)))

/* YX509_ATTRIBUTE */
#define sk_YX509_ATTRIBUTE_new(comp)                 \
  ((STACK_OF(YX509_ATTRIBUTE) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const YX509_ATTRIBUTE **a, const YX509_ATTRIBUTE **b), comp)))

#define sk_YX509_ATTRIBUTE_new_null() ((STACK_OF(YX509_ATTRIBUTE) *)sk_new_null())

#define sk_YX509_ATTRIBUTE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ATTRIBUTE) *, sk))

#define sk_YX509_ATTRIBUTE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk));

#define sk_YX509_ATTRIBUTE_value(sk, i)                                    \
  ((YX509_ATTRIBUTE *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ATTRIBUTE) *, sk), \
      (i)))

#define sk_YX509_ATTRIBUTE_set(sk, i, p)                            \
  ((YX509_ATTRIBUTE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_ATTRIBUTE *, p)))

#define sk_YX509_ATTRIBUTE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk))

#define sk_YX509_ATTRIBUTE_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_ATTRIBUTE *), free_func))

#define sk_YX509_ATTRIBUTE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), \
            CHECKED_YCAST(void *, YX509_ATTRIBUTE *, p), (where))

#define sk_YX509_ATTRIBUTE_delete(sk, where) \
  ((YX509_ATTRIBUTE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), (where)))

#define sk_YX509_ATTRIBUTE_delete_ptr(sk, p)                   \
  ((YX509_ATTRIBUTE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), \
      CHECKED_YCAST(void *, YX509_ATTRIBUTE *, p)))

#define sk_YX509_ATTRIBUTE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_ATTRIBUTE *, p))

#define sk_YX509_ATTRIBUTE_shift(sk) \
  ((YX509_ATTRIBUTE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk)))

#define sk_YX509_ATTRIBUTE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk), \
          CHECKED_YCAST(void *, YX509_ATTRIBUTE *, p))

#define sk_YX509_ATTRIBUTE_pop(sk) \
  ((YX509_ATTRIBUTE *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk)))

#define sk_YX509_ATTRIBUTE_dup(sk)      \
  ((STACK_OF(YX509_ATTRIBUTE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ATTRIBUTE) *, sk)))

#define sk_YX509_ATTRIBUTE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk))

#define sk_YX509_ATTRIBUTE_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ATTRIBUTE) *, sk))

#define sk_YX509_ATTRIBUTE_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_ATTRIBUTE **a, const YX509_ATTRIBUTE **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_ATTRIBUTE) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_ATTRIBUTE **a,  \
                                                const YX509_ATTRIBUTE **b), \
                        comp)))

#define sk_YX509_ATTRIBUTE_deep_copy(sk, copy_func, free_func)                \
  ((STACK_OF(YX509_ATTRIBUTE) *)sk_deep_copy(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_ATTRIBUTE) *, sk),    \
      CHECKED_YCAST(void *(*)(void *), YX509_ATTRIBUTE *(*)(YX509_ATTRIBUTE *), \
                   copy_func),                                               \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_ATTRIBUTE *), free_func)))

/* YX509_CRL */
#define sk_YX509_CRL_new(comp)                 \
  ((STACK_OF(YX509_CRL) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const YX509_CRL **a, const YX509_CRL **b), comp)))

#define sk_YX509_CRL_new_null() ((STACK_OF(YX509_CRL) *)sk_new_null())

#define sk_YX509_CRL_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_CRL) *, sk))

#define sk_YX509_CRL_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk));

#define sk_YX509_CRL_value(sk, i) \
  ((YX509_CRL *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_CRL) *, sk), (i)))

#define sk_YX509_CRL_set(sk, i, p)                                            \
  ((YX509_CRL *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), (i), \
                      CHECKED_YCAST(void *, YX509_CRL *, p)))

#define sk_YX509_CRL_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk))

#define sk_YX509_CRL_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(YX509_CRL *), free_func))

#define sk_YX509_CRL_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), \
            CHECKED_YCAST(void *, YX509_CRL *, p), (where))

#define sk_YX509_CRL_delete(sk, where)                                      \
  ((YX509_CRL *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), \
                         (where)))

#define sk_YX509_CRL_delete_ptr(sk, p)                                          \
  ((YX509_CRL *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), \
                             CHECKED_YCAST(void *, YX509_CRL *, p)))

#define sk_YX509_CRL_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_CRL *, p))

#define sk_YX509_CRL_shift(sk) \
  ((YX509_CRL *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk)))

#define sk_YX509_CRL_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk), \
          CHECKED_YCAST(void *, YX509_CRL *, p))

#define sk_YX509_CRL_pop(sk) \
  ((YX509_CRL *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk)))

#define sk_YX509_CRL_dup(sk)      \
  ((STACK_OF(YX509_CRL) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_CRL) *, sk)))

#define sk_YX509_CRL_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk))

#define sk_YX509_CRL_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_CRL) *, sk))

#define sk_YX509_CRL_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_CRL **a, const YX509_CRL **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_CRL) *, sk),              \
      CHECKED_YCAST(stack_cmp_func,                                   \
                   int (*)(const YX509_CRL **a, const YX509_CRL **b), comp)))

#define sk_YX509_CRL_deep_copy(sk, copy_func, free_func)                      \
  ((STACK_OF(YX509_CRL) *)sk_deep_copy(                                       \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_CRL) *, sk),          \
      CHECKED_YCAST(void *(*)(void *), YX509_CRL *(*)(YX509_CRL *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_CRL *), free_func)))

/* YX509_EXTENSION */
#define sk_YX509_EXTENSION_new(comp)                 \
  ((STACK_OF(YX509_EXTENSION) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const YX509_EXTENSION **a, const YX509_EXTENSION **b), comp)))

#define sk_YX509_EXTENSION_new_null() ((STACK_OF(YX509_EXTENSION) *)sk_new_null())

#define sk_YX509_EXTENSION_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_EXTENSION) *, sk))

#define sk_YX509_EXTENSION_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk));

#define sk_YX509_EXTENSION_value(sk, i)                                    \
  ((YX509_EXTENSION *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_EXTENSION) *, sk), \
      (i)))

#define sk_YX509_EXTENSION_set(sk, i, p)                            \
  ((YX509_EXTENSION *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_EXTENSION *, p)))

#define sk_YX509_EXTENSION_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk))

#define sk_YX509_EXTENSION_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_EXTENSION *), free_func))

#define sk_YX509_EXTENSION_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), \
            CHECKED_YCAST(void *, YX509_EXTENSION *, p), (where))

#define sk_YX509_EXTENSION_delete(sk, where) \
  ((YX509_EXTENSION *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), (where)))

#define sk_YX509_EXTENSION_delete_ptr(sk, p)                   \
  ((YX509_EXTENSION *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), \
      CHECKED_YCAST(void *, YX509_EXTENSION *, p)))

#define sk_YX509_EXTENSION_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_EXTENSION *, p))

#define sk_YX509_EXTENSION_shift(sk) \
  ((YX509_EXTENSION *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk)))

#define sk_YX509_EXTENSION_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk), \
          CHECKED_YCAST(void *, YX509_EXTENSION *, p))

#define sk_YX509_EXTENSION_pop(sk) \
  ((YX509_EXTENSION *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk)))

#define sk_YX509_EXTENSION_dup(sk)      \
  ((STACK_OF(YX509_EXTENSION) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_EXTENSION) *, sk)))

#define sk_YX509_EXTENSION_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk))

#define sk_YX509_EXTENSION_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_EXTENSION) *, sk))

#define sk_YX509_EXTENSION_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_EXTENSION **a, const YX509_EXTENSION **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_EXTENSION) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_EXTENSION **a,  \
                                                const YX509_EXTENSION **b), \
                        comp)))

#define sk_YX509_EXTENSION_deep_copy(sk, copy_func, free_func)                \
  ((STACK_OF(YX509_EXTENSION) *)sk_deep_copy(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_EXTENSION) *, sk),    \
      CHECKED_YCAST(void *(*)(void *), YX509_EXTENSION *(*)(YX509_EXTENSION *), \
                   copy_func),                                               \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_EXTENSION *), free_func)))

/* YX509_INFO */
#define sk_YX509_INFO_new(comp)     \
  ((STACK_OF(YX509_INFO) *)sk_new(  \
      CHECKED_YCAST(stack_cmp_func, \
                   int (*)(const YX509_INFO **a, const YX509_INFO **b), comp)))

#define sk_YX509_INFO_new_null() ((STACK_OF(YX509_INFO) *)sk_new_null())

#define sk_YX509_INFO_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_INFO) *, sk))

#define sk_YX509_INFO_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk));

#define sk_YX509_INFO_value(sk, i) \
  ((YX509_INFO *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_INFO) *, sk), (i)))

#define sk_YX509_INFO_set(sk, i, p)                                             \
  ((YX509_INFO *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), (i), \
                       CHECKED_YCAST(void *, YX509_INFO *, p)))

#define sk_YX509_INFO_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk))

#define sk_YX509_INFO_pop_free(sk, free_func)             \
  sk_pop_free(                                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_INFO *), free_func))

#define sk_YX509_INFO_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), \
            CHECKED_YCAST(void *, YX509_INFO *, p), (where))

#define sk_YX509_INFO_delete(sk, where)                                       \
  ((YX509_INFO *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), \
                          (where)))

#define sk_YX509_INFO_delete_ptr(sk, p)                   \
  ((YX509_INFO *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), \
      CHECKED_YCAST(void *, YX509_INFO *, p)))

#define sk_YX509_INFO_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_INFO *, p))

#define sk_YX509_INFO_shift(sk) \
  ((YX509_INFO *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk)))

#define sk_YX509_INFO_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk), \
          CHECKED_YCAST(void *, YX509_INFO *, p))

#define sk_YX509_INFO_pop(sk) \
  ((YX509_INFO *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk)))

#define sk_YX509_INFO_dup(sk)      \
  ((STACK_OF(YX509_INFO) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_INFO) *, sk)))

#define sk_YX509_INFO_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk))

#define sk_YX509_INFO_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_INFO) *, sk))

#define sk_YX509_INFO_set_cmp_func(sk, comp)                            \
  ((int (*)(const YX509_INFO **a, const YX509_INFO **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_INFO) *, sk),               \
      CHECKED_YCAST(stack_cmp_func,                                     \
                   int (*)(const YX509_INFO **a, const YX509_INFO **b), comp)))

#define sk_YX509_INFO_deep_copy(sk, copy_func, free_func)                       \
  ((STACK_OF(YX509_INFO) *)sk_deep_copy(                                        \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_INFO) *, sk),           \
      CHECKED_YCAST(void *(*)(void *), YX509_INFO *(*)(YX509_INFO *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_INFO *), free_func)))

/* YX509_LOOKUP */
#define sk_YX509_LOOKUP_new(comp)                                             \
  ((STACK_OF(YX509_LOOKUP) *)sk_new(CHECKED_YCAST(                             \
      stack_cmp_func, int (*)(const YX509_LOOKUP **a, const YX509_LOOKUP **b), \
      comp)))

#define sk_YX509_LOOKUP_new_null() ((STACK_OF(YX509_LOOKUP) *)sk_new_null())

#define sk_YX509_LOOKUP_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_LOOKUP) *, sk))

#define sk_YX509_LOOKUP_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk));

#define sk_YX509_LOOKUP_value(sk, i) \
  ((YX509_LOOKUP *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_LOOKUP) *, sk), (i)))

#define sk_YX509_LOOKUP_set(sk, i, p)                                          \
  ((YX509_LOOKUP *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), \
                         (i), CHECKED_YCAST(void *, YX509_LOOKUP *, p)))

#define sk_YX509_LOOKUP_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk))

#define sk_YX509_LOOKUP_pop_free(sk, free_func)             \
  sk_pop_free(                                             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_LOOKUP *), free_func))

#define sk_YX509_LOOKUP_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), \
            CHECKED_YCAST(void *, YX509_LOOKUP *, p), (where))

#define sk_YX509_LOOKUP_delete(sk, where) \
  ((YX509_LOOKUP *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), (where)))

#define sk_YX509_LOOKUP_delete_ptr(sk, p)                   \
  ((YX509_LOOKUP *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), \
      CHECKED_YCAST(void *, YX509_LOOKUP *, p)))

#define sk_YX509_LOOKUP_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_LOOKUP *, p))

#define sk_YX509_LOOKUP_shift(sk) \
  ((YX509_LOOKUP *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk)))

#define sk_YX509_LOOKUP_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk), \
          CHECKED_YCAST(void *, YX509_LOOKUP *, p))

#define sk_YX509_LOOKUP_pop(sk) \
  ((YX509_LOOKUP *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk)))

#define sk_YX509_LOOKUP_dup(sk)      \
  ((STACK_OF(YX509_LOOKUP) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_LOOKUP) *, sk)))

#define sk_YX509_LOOKUP_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk))

#define sk_YX509_LOOKUP_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_LOOKUP) *, sk))

#define sk_YX509_LOOKUP_set_cmp_func(sk, comp)                              \
  ((int (*)(const YX509_LOOKUP **a, const YX509_LOOKUP **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_LOOKUP) *, sk),                 \
      CHECKED_YCAST(stack_cmp_func,                                         \
                   int (*)(const YX509_LOOKUP **a, const YX509_LOOKUP **b),  \
                   comp)))

#define sk_YX509_LOOKUP_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_LOOKUP) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_LOOKUP) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YX509_LOOKUP *(*)(YX509_LOOKUP *), \
                   copy_func),                                         \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_LOOKUP *), free_func)))

/* YX509_NAME */
#define sk_YX509_NAME_new(comp)     \
  ((STACK_OF(YX509_NAME) *)sk_new(  \
      CHECKED_YCAST(stack_cmp_func, \
                   int (*)(const YX509_NAME **a, const YX509_NAME **b), comp)))

#define sk_YX509_NAME_new_null() ((STACK_OF(YX509_NAME) *)sk_new_null())

#define sk_YX509_NAME_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME) *, sk))

#define sk_YX509_NAME_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk));

#define sk_YX509_NAME_value(sk, i) \
  ((YX509_NAME *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME) *, sk), (i)))

#define sk_YX509_NAME_set(sk, i, p)                                             \
  ((YX509_NAME *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), (i), \
                       CHECKED_YCAST(void *, YX509_NAME *, p)))

#define sk_YX509_NAME_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk))

#define sk_YX509_NAME_pop_free(sk, free_func)             \
  sk_pop_free(                                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_NAME *), free_func))

#define sk_YX509_NAME_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), \
            CHECKED_YCAST(void *, YX509_NAME *, p), (where))

#define sk_YX509_NAME_delete(sk, where)                                       \
  ((YX509_NAME *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), \
                          (where)))

#define sk_YX509_NAME_delete_ptr(sk, p)                   \
  ((YX509_NAME *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), \
      CHECKED_YCAST(void *, YX509_NAME *, p)))

#define sk_YX509_NAME_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_NAME *, p))

#define sk_YX509_NAME_shift(sk) \
  ((YX509_NAME *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk)))

#define sk_YX509_NAME_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk), \
          CHECKED_YCAST(void *, YX509_NAME *, p))

#define sk_YX509_NAME_pop(sk) \
  ((YX509_NAME *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk)))

#define sk_YX509_NAME_dup(sk)      \
  ((STACK_OF(YX509_NAME) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME) *, sk)))

#define sk_YX509_NAME_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk))

#define sk_YX509_NAME_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME) *, sk))

#define sk_YX509_NAME_set_cmp_func(sk, comp)                            \
  ((int (*)(const YX509_NAME **a, const YX509_NAME **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME) *, sk),               \
      CHECKED_YCAST(stack_cmp_func,                                     \
                   int (*)(const YX509_NAME **a, const YX509_NAME **b), comp)))

#define sk_YX509_NAME_deep_copy(sk, copy_func, free_func)                       \
  ((STACK_OF(YX509_NAME) *)sk_deep_copy(                                        \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME) *, sk),           \
      CHECKED_YCAST(void *(*)(void *), YX509_NAME *(*)(YX509_NAME *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_NAME *), free_func)))

/* YX509_NAME_ENTRY */
#define sk_YX509_NAME_ENTRY_new(comp)                 \
  ((STACK_OF(YX509_NAME_ENTRY) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                                \
      int (*)(const YX509_NAME_ENTRY **a, const YX509_NAME_ENTRY **b), comp)))

#define sk_YX509_NAME_ENTRY_new_null() \
  ((STACK_OF(YX509_NAME_ENTRY) *)sk_new_null())

#define sk_YX509_NAME_ENTRY_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME_ENTRY) *, sk))

#define sk_YX509_NAME_ENTRY_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk));

#define sk_YX509_NAME_ENTRY_value(sk, i)                                    \
  ((YX509_NAME_ENTRY *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME_ENTRY) *, sk), \
      (i)))

#define sk_YX509_NAME_ENTRY_set(sk, i, p)                            \
  ((YX509_NAME_ENTRY *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_NAME_ENTRY *, p)))

#define sk_YX509_NAME_ENTRY_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk))

#define sk_YX509_NAME_ENTRY_pop_free(sk, free_func)             \
  sk_pop_free(                                                 \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_NAME_ENTRY *), free_func))

#define sk_YX509_NAME_ENTRY_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), \
            CHECKED_YCAST(void *, YX509_NAME_ENTRY *, p), (where))

#define sk_YX509_NAME_ENTRY_delete(sk, where) \
  ((YX509_NAME_ENTRY *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), (where)))

#define sk_YX509_NAME_ENTRY_delete_ptr(sk, p)                   \
  ((YX509_NAME_ENTRY *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), \
      CHECKED_YCAST(void *, YX509_NAME_ENTRY *, p)))

#define sk_YX509_NAME_ENTRY_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), \
          (out_index), CHECKED_YCAST(void *, YX509_NAME_ENTRY *, p))

#define sk_YX509_NAME_ENTRY_shift(sk) \
  ((YX509_NAME_ENTRY *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk)))

#define sk_YX509_NAME_ENTRY_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk), \
          CHECKED_YCAST(void *, YX509_NAME_ENTRY *, p))

#define sk_YX509_NAME_ENTRY_pop(sk) \
  ((YX509_NAME_ENTRY *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk)))

#define sk_YX509_NAME_ENTRY_dup(sk)      \
  ((STACK_OF(YX509_NAME_ENTRY) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME_ENTRY) *, sk)))

#define sk_YX509_NAME_ENTRY_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk))

#define sk_YX509_NAME_ENTRY_is_sorted(sk) \
  sk_is_sorted(                          \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME_ENTRY) *, sk))

#define sk_YX509_NAME_ENTRY_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_NAME_ENTRY **a, const YX509_NAME_ENTRY **b))          \
       sk_set_cmp_func(                                                     \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_NAME_ENTRY) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_NAME_ENTRY **a,  \
                                                const YX509_NAME_ENTRY **b), \
                        comp)))

#define sk_YX509_NAME_ENTRY_deep_copy(sk, copy_func, free_func)                 \
  ((STACK_OF(YX509_NAME_ENTRY) *)sk_deep_copy(                                  \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_NAME_ENTRY) *, sk),     \
      CHECKED_YCAST(void *(*)(void *), YX509_NAME_ENTRY *(*)(YX509_NAME_ENTRY *), \
                   copy_func),                                                 \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_NAME_ENTRY *), free_func)))

/* YX509_OBJECT */
#define sk_YX509_OBJECT_new(comp)                                             \
  ((STACK_OF(YX509_OBJECT) *)sk_new(CHECKED_YCAST(                             \
      stack_cmp_func, int (*)(const YX509_OBJECT **a, const YX509_OBJECT **b), \
      comp)))

#define sk_YX509_OBJECT_new_null() ((STACK_OF(YX509_OBJECT) *)sk_new_null())

#define sk_YX509_OBJECT_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_OBJECT) *, sk))

#define sk_YX509_OBJECT_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk));

#define sk_YX509_OBJECT_value(sk, i) \
  ((YX509_OBJECT *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_OBJECT) *, sk), (i)))

#define sk_YX509_OBJECT_set(sk, i, p)                                          \
  ((YX509_OBJECT *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), \
                         (i), CHECKED_YCAST(void *, YX509_OBJECT *, p)))

#define sk_YX509_OBJECT_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk))

#define sk_YX509_OBJECT_pop_free(sk, free_func)             \
  sk_pop_free(                                             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_OBJECT *), free_func))

#define sk_YX509_OBJECT_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), \
            CHECKED_YCAST(void *, YX509_OBJECT *, p), (where))

#define sk_YX509_OBJECT_delete(sk, where) \
  ((YX509_OBJECT *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), (where)))

#define sk_YX509_OBJECT_delete_ptr(sk, p)                   \
  ((YX509_OBJECT *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), \
      CHECKED_YCAST(void *, YX509_OBJECT *, p)))

#define sk_YX509_OBJECT_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_OBJECT *, p))

#define sk_YX509_OBJECT_shift(sk) \
  ((YX509_OBJECT *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk)))

#define sk_YX509_OBJECT_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk), \
          CHECKED_YCAST(void *, YX509_OBJECT *, p))

#define sk_YX509_OBJECT_pop(sk) \
  ((YX509_OBJECT *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk)))

#define sk_YX509_OBJECT_dup(sk)      \
  ((STACK_OF(YX509_OBJECT) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_OBJECT) *, sk)))

#define sk_YX509_OBJECT_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk))

#define sk_YX509_OBJECT_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_OBJECT) *, sk))

#define sk_YX509_OBJECT_set_cmp_func(sk, comp)                              \
  ((int (*)(const YX509_OBJECT **a, const YX509_OBJECT **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_OBJECT) *, sk),                 \
      CHECKED_YCAST(stack_cmp_func,                                         \
                   int (*)(const YX509_OBJECT **a, const YX509_OBJECT **b),  \
                   comp)))

#define sk_YX509_OBJECT_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_OBJECT) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_OBJECT) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YX509_OBJECT *(*)(YX509_OBJECT *), \
                   copy_func),                                         \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_OBJECT *), free_func)))

/* YX509_POLICY_DATA */
#define sk_YX509_POLICY_DATA_new(comp)                 \
  ((STACK_OF(YX509_POLICY_DATA) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                                 \
      int (*)(const YX509_POLICY_DATA **a, const YX509_POLICY_DATA **b), comp)))

#define sk_YX509_POLICY_DATA_new_null() \
  ((STACK_OF(YX509_POLICY_DATA) *)sk_new_null())

#define sk_YX509_POLICY_DATA_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_DATA) *, sk))

#define sk_YX509_POLICY_DATA_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk));

#define sk_YX509_POLICY_DATA_value(sk, i)                                    \
  ((YX509_POLICY_DATA *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_DATA) *, sk), \
      (i)))

#define sk_YX509_POLICY_DATA_set(sk, i, p)                            \
  ((YX509_POLICY_DATA *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_POLICY_DATA *, p)))

#define sk_YX509_POLICY_DATA_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk))

#define sk_YX509_POLICY_DATA_pop_free(sk, free_func)             \
  sk_pop_free(                                                  \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_POLICY_DATA *), free_func))

#define sk_YX509_POLICY_DATA_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), \
            CHECKED_YCAST(void *, YX509_POLICY_DATA *, p), (where))

#define sk_YX509_POLICY_DATA_delete(sk, where) \
  ((YX509_POLICY_DATA *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), (where)))

#define sk_YX509_POLICY_DATA_delete_ptr(sk, p)                   \
  ((YX509_POLICY_DATA *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), \
      CHECKED_YCAST(void *, YX509_POLICY_DATA *, p)))

#define sk_YX509_POLICY_DATA_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), \
          (out_index), CHECKED_YCAST(void *, YX509_POLICY_DATA *, p))

#define sk_YX509_POLICY_DATA_shift(sk) \
  ((YX509_POLICY_DATA *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk)))

#define sk_YX509_POLICY_DATA_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk), \
          CHECKED_YCAST(void *, YX509_POLICY_DATA *, p))

#define sk_YX509_POLICY_DATA_pop(sk) \
  ((YX509_POLICY_DATA *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk)))

#define sk_YX509_POLICY_DATA_dup(sk)      \
  ((STACK_OF(YX509_POLICY_DATA) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_DATA) *, sk)))

#define sk_YX509_POLICY_DATA_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk))

#define sk_YX509_POLICY_DATA_is_sorted(sk) \
  sk_is_sorted(                           \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_DATA) *, sk))

#define sk_YX509_POLICY_DATA_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_POLICY_DATA **a, const YX509_POLICY_DATA **b))         \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_DATA) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_POLICY_DATA **a,  \
                                                const YX509_POLICY_DATA **b), \
                        comp)))

#define sk_YX509_POLICY_DATA_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_POLICY_DATA) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_DATA) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                       \
                   YX509_POLICY_DATA *(*)(YX509_POLICY_DATA *), copy_func),   \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_POLICY_DATA *),          \
                   free_func)))

/* YX509_POLICY_NODE */
#define sk_YX509_POLICY_NODE_new(comp)                 \
  ((STACK_OF(YX509_POLICY_NODE) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                                 \
      int (*)(const YX509_POLICY_NODE **a, const YX509_POLICY_NODE **b), comp)))

#define sk_YX509_POLICY_NODE_new_null() \
  ((STACK_OF(YX509_POLICY_NODE) *)sk_new_null())

#define sk_YX509_POLICY_NODE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_NODE) *, sk))

#define sk_YX509_POLICY_NODE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk));

#define sk_YX509_POLICY_NODE_value(sk, i)                                    \
  ((YX509_POLICY_NODE *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_NODE) *, sk), \
      (i)))

#define sk_YX509_POLICY_NODE_set(sk, i, p)                            \
  ((YX509_POLICY_NODE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_POLICY_NODE *, p)))

#define sk_YX509_POLICY_NODE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk))

#define sk_YX509_POLICY_NODE_pop_free(sk, free_func)             \
  sk_pop_free(                                                  \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_POLICY_NODE *), free_func))

#define sk_YX509_POLICY_NODE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), \
            CHECKED_YCAST(void *, YX509_POLICY_NODE *, p), (where))

#define sk_YX509_POLICY_NODE_delete(sk, where) \
  ((YX509_POLICY_NODE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), (where)))

#define sk_YX509_POLICY_NODE_delete_ptr(sk, p)                   \
  ((YX509_POLICY_NODE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), \
      CHECKED_YCAST(void *, YX509_POLICY_NODE *, p)))

#define sk_YX509_POLICY_NODE_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), \
          (out_index), CHECKED_YCAST(void *, YX509_POLICY_NODE *, p))

#define sk_YX509_POLICY_NODE_shift(sk) \
  ((YX509_POLICY_NODE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk)))

#define sk_YX509_POLICY_NODE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk), \
          CHECKED_YCAST(void *, YX509_POLICY_NODE *, p))

#define sk_YX509_POLICY_NODE_pop(sk) \
  ((YX509_POLICY_NODE *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk)))

#define sk_YX509_POLICY_NODE_dup(sk)      \
  ((STACK_OF(YX509_POLICY_NODE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_NODE) *, sk)))

#define sk_YX509_POLICY_NODE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk))

#define sk_YX509_POLICY_NODE_is_sorted(sk) \
  sk_is_sorted(                           \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_NODE) *, sk))

#define sk_YX509_POLICY_NODE_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_POLICY_NODE **a, const YX509_POLICY_NODE **b))         \
       sk_set_cmp_func(                                                      \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_POLICY_NODE) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_POLICY_NODE **a,  \
                                                const YX509_POLICY_NODE **b), \
                        comp)))

#define sk_YX509_POLICY_NODE_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_POLICY_NODE) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_POLICY_NODE) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                       \
                   YX509_POLICY_NODE *(*)(YX509_POLICY_NODE *), copy_func),   \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_POLICY_NODE *),          \
                   free_func)))

/* YX509_PURPOSE */
#define sk_YX509_PURPOSE_new(comp)                                              \
  ((STACK_OF(YX509_PURPOSE) *)sk_new(CHECKED_YCAST(                              \
      stack_cmp_func, int (*)(const YX509_PURPOSE **a, const YX509_PURPOSE **b), \
      comp)))

#define sk_YX509_PURPOSE_new_null() ((STACK_OF(YX509_PURPOSE) *)sk_new_null())

#define sk_YX509_PURPOSE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_PURPOSE) *, sk))

#define sk_YX509_PURPOSE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk));

#define sk_YX509_PURPOSE_value(sk, i) \
  ((YX509_PURPOSE *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_PURPOSE) *, sk), (i)))

#define sk_YX509_PURPOSE_set(sk, i, p)                            \
  ((YX509_PURPOSE *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_PURPOSE *, p)))

#define sk_YX509_PURPOSE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk))

#define sk_YX509_PURPOSE_pop_free(sk, free_func)             \
  sk_pop_free(                                              \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_PURPOSE *), free_func))

#define sk_YX509_PURPOSE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), \
            CHECKED_YCAST(void *, YX509_PURPOSE *, p), (where))

#define sk_YX509_PURPOSE_delete(sk, where) \
  ((YX509_PURPOSE *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), (where)))

#define sk_YX509_PURPOSE_delete_ptr(sk, p)                   \
  ((YX509_PURPOSE *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), \
      CHECKED_YCAST(void *, YX509_PURPOSE *, p)))

#define sk_YX509_PURPOSE_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_PURPOSE *, p))

#define sk_YX509_PURPOSE_shift(sk) \
  ((YX509_PURPOSE *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk)))

#define sk_YX509_PURPOSE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk), \
          CHECKED_YCAST(void *, YX509_PURPOSE *, p))

#define sk_YX509_PURPOSE_pop(sk) \
  ((YX509_PURPOSE *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk)))

#define sk_YX509_PURPOSE_dup(sk)      \
  ((STACK_OF(YX509_PURPOSE) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_PURPOSE) *, sk)))

#define sk_YX509_PURPOSE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk))

#define sk_YX509_PURPOSE_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_PURPOSE) *, sk))

#define sk_YX509_PURPOSE_set_cmp_func(sk, comp)                               \
  ((int (*)(const YX509_PURPOSE **a, const YX509_PURPOSE **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_PURPOSE) *, sk),                  \
      CHECKED_YCAST(stack_cmp_func,                                           \
                   int (*)(const YX509_PURPOSE **a, const YX509_PURPOSE **b),  \
                   comp)))

#define sk_YX509_PURPOSE_deep_copy(sk, copy_func, free_func)              \
  ((STACK_OF(YX509_PURPOSE) *)sk_deep_copy(                               \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_PURPOSE) *, sk),  \
      CHECKED_YCAST(void *(*)(void *), YX509_PURPOSE *(*)(YX509_PURPOSE *), \
                   copy_func),                                           \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_PURPOSE *), free_func)))

/* YX509_REVOKED */
#define sk_YX509_REVOKED_new(comp)                                              \
  ((STACK_OF(YX509_REVOKED) *)sk_new(CHECKED_YCAST(                              \
      stack_cmp_func, int (*)(const YX509_REVOKED **a, const YX509_REVOKED **b), \
      comp)))

#define sk_YX509_REVOKED_new_null() ((STACK_OF(YX509_REVOKED) *)sk_new_null())

#define sk_YX509_REVOKED_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_REVOKED) *, sk))

#define sk_YX509_REVOKED_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk));

#define sk_YX509_REVOKED_value(sk, i) \
  ((YX509_REVOKED *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_REVOKED) *, sk), (i)))

#define sk_YX509_REVOKED_set(sk, i, p)                            \
  ((YX509_REVOKED *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_REVOKED *, p)))

#define sk_YX509_REVOKED_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk))

#define sk_YX509_REVOKED_pop_free(sk, free_func)             \
  sk_pop_free(                                              \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_REVOKED *), free_func))

#define sk_YX509_REVOKED_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), \
            CHECKED_YCAST(void *, YX509_REVOKED *, p), (where))

#define sk_YX509_REVOKED_delete(sk, where) \
  ((YX509_REVOKED *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), (where)))

#define sk_YX509_REVOKED_delete_ptr(sk, p)                   \
  ((YX509_REVOKED *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), \
      CHECKED_YCAST(void *, YX509_REVOKED *, p)))

#define sk_YX509_REVOKED_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_REVOKED *, p))

#define sk_YX509_REVOKED_shift(sk) \
  ((YX509_REVOKED *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk)))

#define sk_YX509_REVOKED_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk), \
          CHECKED_YCAST(void *, YX509_REVOKED *, p))

#define sk_YX509_REVOKED_pop(sk) \
  ((YX509_REVOKED *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk)))

#define sk_YX509_REVOKED_dup(sk)      \
  ((STACK_OF(YX509_REVOKED) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_REVOKED) *, sk)))

#define sk_YX509_REVOKED_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk))

#define sk_YX509_REVOKED_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_REVOKED) *, sk))

#define sk_YX509_REVOKED_set_cmp_func(sk, comp)                               \
  ((int (*)(const YX509_REVOKED **a, const YX509_REVOKED **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_REVOKED) *, sk),                  \
      CHECKED_YCAST(stack_cmp_func,                                           \
                   int (*)(const YX509_REVOKED **a, const YX509_REVOKED **b),  \
                   comp)))

#define sk_YX509_REVOKED_deep_copy(sk, copy_func, free_func)              \
  ((STACK_OF(YX509_REVOKED) *)sk_deep_copy(                               \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_REVOKED) *, sk),  \
      CHECKED_YCAST(void *(*)(void *), YX509_REVOKED *(*)(YX509_REVOKED *), \
                   copy_func),                                           \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_REVOKED *), free_func)))

/* YX509_TRUST */
#define sk_YX509_TRUST_new(comp)                                            \
  ((STACK_OF(YX509_TRUST) *)sk_new(CHECKED_YCAST(                            \
      stack_cmp_func, int (*)(const YX509_TRUST **a, const YX509_TRUST **b), \
      comp)))

#define sk_YX509_TRUST_new_null() ((STACK_OF(YX509_TRUST) *)sk_new_null())

#define sk_YX509_TRUST_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_TRUST) *, sk))

#define sk_YX509_TRUST_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk));

#define sk_YX509_TRUST_value(sk, i) \
  ((YX509_TRUST *)sk_value(         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_TRUST) *, sk), (i)))

#define sk_YX509_TRUST_set(sk, i, p)                                         \
  ((YX509_TRUST *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
                        (i), CHECKED_YCAST(void *, YX509_TRUST *, p)))

#define sk_YX509_TRUST_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk))

#define sk_YX509_TRUST_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_TRUST *), free_func))

#define sk_YX509_TRUST_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
            CHECKED_YCAST(void *, YX509_TRUST *, p), (where))

#define sk_YX509_TRUST_delete(sk, where)                                        \
  ((YX509_TRUST *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
                           (where)))

#define sk_YX509_TRUST_delete_ptr(sk, p)                   \
  ((YX509_TRUST *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
      CHECKED_YCAST(void *, YX509_TRUST *, p)))

#define sk_YX509_TRUST_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), (out_index), \
          CHECKED_YCAST(void *, YX509_TRUST *, p))

#define sk_YX509_TRUST_shift(sk) \
  ((YX509_TRUST *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk)))

#define sk_YX509_TRUST_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk), \
          CHECKED_YCAST(void *, YX509_TRUST *, p))

#define sk_YX509_TRUST_pop(sk) \
  ((YX509_TRUST *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk)))

#define sk_YX509_TRUST_dup(sk)      \
  ((STACK_OF(YX509_TRUST) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_TRUST) *, sk)))

#define sk_YX509_TRUST_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk))

#define sk_YX509_TRUST_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_TRUST) *, sk))

#define sk_YX509_TRUST_set_cmp_func(sk, comp)                             \
  ((int (*)(const YX509_TRUST **a, const YX509_TRUST **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_TRUST) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const YX509_TRUST **a, const YX509_TRUST **b),  \
                   comp)))

#define sk_YX509_TRUST_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_TRUST) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_TRUST) *, sk), \
      CHECKED_YCAST(void *(*)(void *), YX509_TRUST *(*)(YX509_TRUST *),  \
                   copy_func),                                        \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_TRUST *), free_func)))

/* YX509_VERIFY_PARAM */
#define sk_YX509_VERIFY_PARAM_new(comp)                                   \
  ((STACK_OF(YX509_VERIFY_PARAM) *)sk_new(CHECKED_YCAST(                   \
      stack_cmp_func,                                                    \
      int (*)(const YX509_VERIFY_PARAM **a, const YX509_VERIFY_PARAM **b), \
      comp)))

#define sk_YX509_VERIFY_PARAM_new_null() \
  ((STACK_OF(YX509_VERIFY_PARAM) *)sk_new_null())

#define sk_YX509_VERIFY_PARAM_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_VERIFY_PARAM) *, sk))

#define sk_YX509_VERIFY_PARAM_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk));

#define sk_YX509_VERIFY_PARAM_value(sk, i)                                    \
  ((YX509_VERIFY_PARAM *)sk_value(                                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_VERIFY_PARAM) *, sk), \
      (i)))

#define sk_YX509_VERIFY_PARAM_set(sk, i, p)                            \
  ((YX509_VERIFY_PARAM *)sk_set(                                       \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), (i), \
      CHECKED_YCAST(void *, YX509_VERIFY_PARAM *, p)))

#define sk_YX509_VERIFY_PARAM_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk))

#define sk_YX509_VERIFY_PARAM_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk),    \
              CHECKED_YCAST(void (*)(void *), void (*)(YX509_VERIFY_PARAM *), \
                           free_func))

#define sk_YX509_VERIFY_PARAM_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), \
            CHECKED_YCAST(void *, YX509_VERIFY_PARAM *, p), (where))

#define sk_YX509_VERIFY_PARAM_delete(sk, where) \
  ((YX509_VERIFY_PARAM *)sk_delete(             \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), (where)))

#define sk_YX509_VERIFY_PARAM_delete_ptr(sk, p)                   \
  ((YX509_VERIFY_PARAM *)sk_delete_ptr(                           \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), \
      CHECKED_YCAST(void *, YX509_VERIFY_PARAM *, p)))

#define sk_YX509_VERIFY_PARAM_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), \
          (out_index), CHECKED_YCAST(void *, YX509_VERIFY_PARAM *, p))

#define sk_YX509_VERIFY_PARAM_shift(sk) \
  ((YX509_VERIFY_PARAM *)sk_shift(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk)))

#define sk_YX509_VERIFY_PARAM_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk), \
          CHECKED_YCAST(void *, YX509_VERIFY_PARAM *, p))

#define sk_YX509_VERIFY_PARAM_pop(sk) \
  ((YX509_VERIFY_PARAM *)sk_pop(      \
      CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk)))

#define sk_YX509_VERIFY_PARAM_dup(sk)      \
  ((STACK_OF(YX509_VERIFY_PARAM) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_VERIFY_PARAM) *, sk)))

#define sk_YX509_VERIFY_PARAM_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk))

#define sk_YX509_VERIFY_PARAM_is_sorted(sk) \
  sk_is_sorted(                            \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_VERIFY_PARAM) *, sk))

#define sk_YX509_VERIFY_PARAM_set_cmp_func(sk, comp)                           \
  ((int (*)(const YX509_VERIFY_PARAM **a, const YX509_VERIFY_PARAM **b))        \
       sk_set_cmp_func(                                                       \
           CHECKED_YCAST(_STACK *, STACK_OF(YX509_VERIFY_PARAM) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const YX509_VERIFY_PARAM **a,  \
                                                const YX509_VERIFY_PARAM **b), \
                        comp)))

#define sk_YX509_VERIFY_PARAM_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(YX509_VERIFY_PARAM) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(YX509_VERIFY_PARAM) *, sk), \
      CHECKED_YCAST(void *(*)(void *),                                        \
                   YX509_VERIFY_PARAM *(*)(YX509_VERIFY_PARAM *), copy_func),  \
      CHECKED_YCAST(void (*)(void *), void (*)(YX509_VERIFY_PARAM *),          \
                   free_func)))

/* void */
#define sk_void_new(comp)                 \
  ((STACK_OF(void) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func, int (*)(const void **a, const void **b), comp)))

#define sk_void_new_null() ((STACK_OF(void) *)sk_new_null())

#define sk_void_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(void) *, sk))

#define sk_void_zero(sk) sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk));

#define sk_void_value(sk, i)                                                  \
  ((void *)sk_value(CHECKED_YCAST(const _STACK *, const STACK_OF(void) *, sk), \
                    (i)))

#define sk_void_set(sk, i, p)                                        \
  ((void *)sk_set(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), (i), \
                  CHECKED_YCAST(void *, void *, p)))

#define sk_void_free(sk) sk_free(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk))

#define sk_void_pop_free(sk, free_func)                     \
  sk_pop_free(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), \
              CHECKED_YCAST(void (*)(void *), void (*)(void *), free_func))

#define sk_void_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), \
            CHECKED_YCAST(void *, void *, p), (where))

#define sk_void_delete(sk, where) \
  ((void *)sk_delete(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), (where)))

#define sk_void_delete_ptr(sk, p)                                      \
  ((void *)sk_delete_ptr(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), \
                         CHECKED_YCAST(void *, void *, p)))

#define sk_void_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), (out_index), \
          CHECKED_YCAST(void *, void *, p))

#define sk_void_shift(sk) \
  ((void *)sk_shift(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk)))

#define sk_void_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk), \
          CHECKED_YCAST(void *, void *, p))

#define sk_void_pop(sk) \
  ((void *)sk_pop(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk)))

#define sk_void_dup(sk)      \
  ((STACK_OF(void) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(void) *, sk)))

#define sk_void_sort(sk) sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk))

#define sk_void_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(void) *, sk))

#define sk_void_set_cmp_func(sk, comp)                                      \
  ((int (*)(const void **a, const void **b))sk_set_cmp_func(                \
      CHECKED_YCAST(_STACK *, STACK_OF(void) *, sk),                         \
      CHECKED_YCAST(stack_cmp_func, int (*)(const void **a, const void **b), \
                   comp)))

#define sk_void_deep_copy(sk, copy_func, free_func)                  \
  ((STACK_OF(void) *)sk_deep_copy(                                   \
      CHECKED_YCAST(const _STACK *, const STACK_OF(void) *, sk),      \
      CHECKED_YCAST(void *(*)(void *), void *(*)(void *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(void *), free_func)))

/* SRTP_PROTECTION_PROFILE */
#define sk_SRTP_PROTECTION_PROFILE_new(comp)                            \
  ((STACK_OF(SRTP_PROTECTION_PROFILE) *)sk_new(CHECKED_YCAST(            \
      stack_cmp_func, int (*)(const const SRTP_PROTECTION_PROFILE **a,  \
                              const const SRTP_PROTECTION_PROFILE **b), \
      comp)))

#define sk_SRTP_PROTECTION_PROFILE_new_null() \
  ((STACK_OF(SRTP_PROTECTION_PROFILE) *)sk_new_null())

#define sk_SRTP_PROTECTION_PROFILE_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *,      \
                      const STACK_OF(SRTP_PROTECTION_PROFILE) *, sk))

#define sk_SRTP_PROTECTION_PROFILE_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk));

#define sk_SRTP_PROTECTION_PROFILE_value(sk, i)                               \
  ((const SRTP_PROTECTION_PROFILE *)sk_value(                                 \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SRTP_PROTECTION_PROFILE) *, \
                   sk),                                                       \
      (i)))

#define sk_SRTP_PROTECTION_PROFILE_set(sk, i, p)                            \
  ((const SRTP_PROTECTION_PROFILE *)sk_set(                                 \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), (i), \
      CHECKED_YCAST(void *, const SRTP_PROTECTION_PROFILE *, p)))

#define sk_SRTP_PROTECTION_PROFILE_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk))

#define sk_SRTP_PROTECTION_PROFILE_pop_free(sk, free_func)             \
  sk_pop_free(                                                         \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
      CHECKED_YCAST(void (*)(void *),                                   \
                   void (*)(const SRTP_PROTECTION_PROFILE *), free_func))

#define sk_SRTP_PROTECTION_PROFILE_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
            CHECKED_YCAST(void *, const SRTP_PROTECTION_PROFILE *, p), (where))

#define sk_SRTP_PROTECTION_PROFILE_delete(sk, where)                   \
  ((const SRTP_PROTECTION_PROFILE *)sk_delete(                         \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
      (where)))

#define sk_SRTP_PROTECTION_PROFILE_delete_ptr(sk, p)                   \
  ((const SRTP_PROTECTION_PROFILE *)sk_delete_ptr(                     \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
      CHECKED_YCAST(void *, const SRTP_PROTECTION_PROFILE *, p)))

#define sk_SRTP_PROTECTION_PROFILE_find(sk, out_index, p)                  \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
          (out_index),                                                     \
          CHECKED_YCAST(void *, const SRTP_PROTECTION_PROFILE *, p))

#define sk_SRTP_PROTECTION_PROFILE_shift(sk)  \
  ((const SRTP_PROTECTION_PROFILE *)sk_shift( \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk)))

#define sk_SRTP_PROTECTION_PROFILE_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
          CHECKED_YCAST(void *, const SRTP_PROTECTION_PROFILE *, p))

#define sk_SRTP_PROTECTION_PROFILE_pop(sk)  \
  ((const SRTP_PROTECTION_PROFILE *)sk_pop( \
      CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk)))

#define sk_SRTP_PROTECTION_PROFILE_dup(sk)                   \
  ((STACK_OF(SRTP_PROTECTION_PROFILE) *)sk_dup(CHECKED_YCAST( \
      const _STACK *, const STACK_OF(SRTP_PROTECTION_PROFILE) *, sk)))

#define sk_SRTP_PROTECTION_PROFILE_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk))

#define sk_SRTP_PROTECTION_PROFILE_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *,      \
                            const STACK_OF(SRTP_PROTECTION_PROFILE) *, sk))

#define sk_SRTP_PROTECTION_PROFILE_set_cmp_func(sk, comp)                   \
  ((int (*)(const SRTP_PROTECTION_PROFILE **a,                              \
            const SRTP_PROTECTION_PROFILE **b))                             \
       sk_set_cmp_func(                                                     \
           CHECKED_YCAST(_STACK *, STACK_OF(SRTP_PROTECTION_PROFILE) *, sk), \
           CHECKED_YCAST(stack_cmp_func,                                     \
                        int (*)(const SRTP_PROTECTION_PROFILE **a,          \
                                const SRTP_PROTECTION_PROFILE **b),         \
                        comp)))

#define sk_SRTP_PROTECTION_PROFILE_deep_copy(sk, copy_func, free_func)         \
  ((STACK_OF(SRTP_PROTECTION_PROFILE) *)sk_deep_copy(                          \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SRTP_PROTECTION_PROFILE) *,  \
                   sk),                                                        \
      CHECKED_YCAST(                                                            \
          void *(*)(void *),                                                   \
          const SRTP_PROTECTION_PROFILE *(*)(const SRTP_PROTECTION_PROFILE *), \
          copy_func),                                                          \
      CHECKED_YCAST(void (*)(void *),                                           \
                   void (*)(const SRTP_PROTECTION_PROFILE *), free_func)))

/* SSL_CIPHER */
#define sk_SSL_CIPHER_new(comp)                 \
  ((STACK_OF(SSL_CIPHER) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                           \
      int (*)(const const SSL_CIPHER **a, const const SSL_CIPHER **b), comp)))

#define sk_SSL_CIPHER_new_null() ((STACK_OF(SSL_CIPHER) *)sk_new_null())

#define sk_SSL_CIPHER_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CIPHER) *, sk))

#define sk_SSL_CIPHER_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk));

#define sk_SSL_CIPHER_value(sk, i) \
  ((const SSL_CIPHER *)sk_value(   \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CIPHER) *, sk), (i)))

#define sk_SSL_CIPHER_set(sk, i, p)                            \
  ((const SSL_CIPHER *)sk_set(                                 \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), (i), \
      CHECKED_YCAST(void *, const SSL_CIPHER *, p)))

#define sk_SSL_CIPHER_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk))

#define sk_SSL_CIPHER_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(const SSL_CIPHER *), free_func))

#define sk_SSL_CIPHER_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), \
            CHECKED_YCAST(void *, const SSL_CIPHER *, p), (where))

#define sk_SSL_CIPHER_delete(sk, where) \
  ((const SSL_CIPHER *)sk_delete(       \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), (where)))

#define sk_SSL_CIPHER_delete_ptr(sk, p)                   \
  ((const SSL_CIPHER *)sk_delete_ptr(                     \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), \
      CHECKED_YCAST(void *, const SSL_CIPHER *, p)))

#define sk_SSL_CIPHER_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), (out_index), \
          CHECKED_YCAST(void *, const SSL_CIPHER *, p))

#define sk_SSL_CIPHER_shift(sk)  \
  ((const SSL_CIPHER *)sk_shift( \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk)))

#define sk_SSL_CIPHER_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk), \
          CHECKED_YCAST(void *, const SSL_CIPHER *, p))

#define sk_SSL_CIPHER_pop(sk)  \
  ((const SSL_CIPHER *)sk_pop( \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk)))

#define sk_SSL_CIPHER_dup(sk)      \
  ((STACK_OF(SSL_CIPHER) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CIPHER) *, sk)))

#define sk_SSL_CIPHER_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk))

#define sk_SSL_CIPHER_is_sorted(sk) \
  sk_is_sorted(CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CIPHER) *, sk))

#define sk_SSL_CIPHER_set_cmp_func(sk, comp)                             \
  ((int (*)(const SSL_CIPHER **a, const SSL_CIPHER **b))sk_set_cmp_func( \
      CHECKED_YCAST(_STACK *, STACK_OF(SSL_CIPHER) *, sk),                \
      CHECKED_YCAST(stack_cmp_func,                                       \
                   int (*)(const SSL_CIPHER **a, const SSL_CIPHER **b),  \
                   comp)))

#define sk_SSL_CIPHER_deep_copy(sk, copy_func, free_func)                 \
  ((STACK_OF(SSL_CIPHER) *)sk_deep_copy(                                  \
      CHECKED_YCAST(const _STACK *, const STACK_OF(SSL_CIPHER) *, sk),     \
      CHECKED_YCAST(void *(*)(void *),                                     \
                   const SSL_CIPHER *(*)(const SSL_CIPHER *), copy_func), \
      CHECKED_YCAST(void (*)(void *), void (*)(const SSL_CIPHER *),        \
                   free_func)))

/* OPENSSL_STRING */
#define sk_OPENSSL_STRING_new(comp)                 \
  ((STACK_OF(OPENSSL_STRING) *)sk_new(CHECKED_YCAST( \
      stack_cmp_func,                               \
      int (*)(const OPENSSL_STRING *a, const OPENSSL_STRING *b), comp)))

#define sk_OPENSSL_STRING_new_null() ((STACK_OF(OPENSSL_STRING) *)sk_new_null())

#define sk_OPENSSL_STRING_num(sk) \
  sk_num(CHECKED_YCAST(const _STACK *, const STACK_OF(OPENSSL_STRING) *, sk))

#define sk_OPENSSL_STRING_zero(sk) \
  sk_zero(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk));

#define sk_OPENSSL_STRING_value(sk, i)                                    \
  ((OPENSSL_STRING)sk_value(                                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(OPENSSL_STRING) *, sk), \
      (i)))

#define sk_OPENSSL_STRING_set(sk, i, p)                            \
  ((OPENSSL_STRING)sk_set(                                         \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), (i), \
      CHECKED_YCAST(void *, OPENSSL_STRING, p)))

#define sk_OPENSSL_STRING_free(sk) \
  sk_free(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk))

#define sk_OPENSSL_STRING_pop_free(sk, free_func)             \
  sk_pop_free(                                                \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), \
      CHECKED_YCAST(void (*)(void *), void (*)(OPENSSL_STRING), free_func))

#define sk_OPENSSL_STRING_insert(sk, p, where)                      \
  sk_insert(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), \
            CHECKED_YCAST(void *, OPENSSL_STRING, p), (where))

#define sk_OPENSSL_STRING_delete(sk, where) \
  ((OPENSSL_STRING)sk_delete(               \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), (where)))

#define sk_OPENSSL_STRING_delete_ptr(sk, p)                   \
  ((OPENSSL_STRING)sk_delete_ptr(                             \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), \
      CHECKED_YCAST(void *, OPENSSL_STRING, p)))

#define sk_OPENSSL_STRING_find(sk, out_index, p)                               \
  sk_find(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), (out_index), \
          CHECKED_YCAST(void *, OPENSSL_STRING, p))

#define sk_OPENSSL_STRING_shift(sk) \
  ((OPENSSL_STRING)sk_shift(        \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk)))

#define sk_OPENSSL_STRING_push(sk, p)                             \
  sk_push(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk), \
          CHECKED_YCAST(void *, OPENSSL_STRING, p))

#define sk_OPENSSL_STRING_pop(sk) \
  ((OPENSSL_STRING)sk_pop(        \
      CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk)))

#define sk_OPENSSL_STRING_dup(sk)      \
  ((STACK_OF(OPENSSL_STRING) *)sk_dup( \
      CHECKED_YCAST(const _STACK *, const STACK_OF(OPENSSL_STRING) *, sk)))

#define sk_OPENSSL_STRING_sort(sk) \
  sk_sort(CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk))

#define sk_OPENSSL_STRING_is_sorted(sk) \
  sk_is_sorted(                         \
      CHECKED_YCAST(const _STACK *, const STACK_OF(OPENSSL_STRING) *, sk))

#define sk_OPENSSL_STRING_set_cmp_func(sk, comp)                           \
  ((int (*)(const OPENSSL_STRING **a, const OPENSSL_STRING **b))           \
       sk_set_cmp_func(                                                    \
           CHECKED_YCAST(_STACK *, STACK_OF(OPENSSL_STRING) *, sk),         \
           CHECKED_YCAST(stack_cmp_func, int (*)(const OPENSSL_STRING **a,  \
                                                const OPENSSL_STRING **b), \
                        comp)))

#define sk_OPENSSL_STRING_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(OPENSSL_STRING) *)sk_deep_copy(                              \
      CHECKED_YCAST(const _STACK *, const STACK_OF(OPENSSL_STRING) *, sk), \
      CHECKED_YCAST(void *(*)(void *), OPENSSL_STRING (*)(OPENSSL_STRING), \
                   copy_func),                                            \
      CHECKED_YCAST(void (*)(void *), void (*)(OPENSSL_STRING), free_func)))
