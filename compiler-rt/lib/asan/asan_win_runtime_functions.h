//===-- asan_win_runtime_functions.h ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Contains function definitions for the C Runtime functions that asan will
// intercept.
//===----------------------------------------------------------------------===//
#pragma once

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

#if SANITIZER_WINDOWS

#if ASAN_DYNAMIC
#define ALLOCATION_FUNCTION_ATTRIBUTE
#else
#define ALLOCATION_FUNCTION_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE
#endif

extern "C" {
ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize(void *ptr);

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize_base(void *ptr);

ALLOCATION_FUNCTION_ATTRIBUTE
void free(void *ptr);

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_base(void *ptr);

ALLOCATION_FUNCTION_ATTRIBUTE
void *malloc(size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_malloc_base(size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *calloc(size_t nmemb, size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_base(size_t nmemb, size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_impl(size_t nmemb, size_t size, int *errno_tmp);

ALLOCATION_FUNCTION_ATTRIBUTE
void *realloc(void *ptr, size_t size);
ALLOCATION_FUNCTION_ATTRIBUTE
void *_realloc_base(void *ptr, size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc(void *p, size_t n, size_t elem_size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc_base(void *p, size_t n, size_t elem_size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_expand(void *memblock, size_t size);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_malloc(size_t size, size_t alignment);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_malloc(size_t size, size_t alignment, size_t);

ALLOCATION_FUNCTION_ATTRIBUTE
void _aligned_free(void *memblock);

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _aligned_msize(void *memblock, size_t alignment, size_t offset);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_realloc(void *memblock, size_t size, size_t alignment);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_realloc(void *memblock, size_t size, size_t alignment,
                              size_t);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_recalloc(void *memblock, size_t num, size_t element_size,
                        size_t alignment);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_recalloc(void *memblock, size_t num, size_t element_size,
                               size_t alignment, size_t);

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _aligned_msize_dbg(void *memblock, size_t alignment, size_t offset);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_malloc_dbg(size_t size, int, const char *, int);

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_dbg(void *ptr, int);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_expand_dbg(void *memblock, size_t size, int, const char *, int);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_dbg(size_t nmemb, size_t size, int, const char *, int);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_realloc_dbg(void *ptr, size_t size, int, const char *, int);
ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc_dbg(void *userData, size_t num, size_t size, int, const char *,
                    int);

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize_dbg(void *userData, int);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_malloc_dbg(size_t const size, size_t const alignment,
                          char const *const, int const);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_malloc_dbg(size_t const size, size_t const alignment,
                                 size_t const offset, char const *const,
                                 int const);
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_realloc_dbg(void *const block, size_t const size,
                           size_t const alignment, char const *const,
                           int const);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_realloc_dbg(void *const block, size_t const size,
                                  size_t const alignment, size_t const offset,
                                  char const *const, int const);

ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_recalloc_dbg(void *const block, size_t const count,
                            size_t const element_size, size_t const alignment,
                            char const *const, int const);

// We don't respect the offset
ALLOCATION_FUNCTION_ATTRIBUTE
void *_aligned_offset_recalloc_dbg(void *const block, size_t const count,
                                   size_t const element_size,
                                   size_t const alignment, size_t const offset,
                                   char const *const, int const);

ALLOCATION_FUNCTION_ATTRIBUTE
void _aligned_free_dbg(void *const block);
}  // extern "C"

namespace __asan {

void OverrideFunctionsForEachCrt();

}  // namespace __asan
#endif