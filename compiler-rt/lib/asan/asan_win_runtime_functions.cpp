//===-- asan_win_runtime_functions.cpp ---------------------------*- C++-*-===//
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

// __RuntimeFunctions class contains two key features:
//
// 1. List of function pointers that will be used for each function from a
// version of the crt. These function pointers are populated by the
// OverrideFunctions call and will be set once on asan initialization depending
// on which runtimes are present. This is especially important for functions
// that allocate memory themselves prior to ASAN initialization and have the
// capacity to manipulate that memory after ASAN is initialized. Ex:
// _setmaxstdio reallocates __piob, which is allocated prior to asan
// initialization
//
// 2. Several static functions that contain the logic for determining which
// function to route the call. If the memory that is passed into the runtime
// function was allocated prior to ASAN initialization, the functions will
// forward the arguments to a corresponding runtime function if it does not
// manipulate memory. If it does manipulate memory, the asan runtime will need
// to take ownership of that memory and remove tracking from the
// SystemHeapAllocationsMap. If the memory was allocated after ASAN
// initialization, the functions will use the ASAN runtime.
//
// In order to get around the reported call stack on errors back to a consumer
// of asan having something like "__RuntimeFunctions::Function" inserted into it
// between the user's function and the actual asan or crt function called, we
// avoid any code that the optimizer might not attempt to optimize, such as
// passing the crt function pointers by address to another function.
// CHECK_AND_CALL, CHECK_AND_CALL_FREE,
// and SWITCH_TO_ASAN_ALLOCATION are macros
// defined at the top of this file used depending on the context. CHECK_AND_CALL
// variants are used for functions that wouldn't need to reallocate from asan.
// SWITCH_TO_ASAN_ALLOCATION is used for functions that will need to reallocate
// from asan after a crt call.

#include "asan_win_runtime_functions.h"

#ifdef SANITIZER_WINDOWS

/* Memory block identification taken from /minkernel/crts/ucrt/inc/crtdbg.h */
#ifndef _NORMAL_BLOCK
#define _NORMAL_BLOCK 1
#endif

#include "asan_allocator.h"
#include "asan_flags.h"
#include "asan_interceptors_memintrinsics.h"
#include "asan_interface_internal.h"
#include "asan_internal.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

namespace __asan {

// Checks whether or not a block of memory was allocated prior to asan
// initialization given two function pointers to functions that manipulate
// memory. These are crt functions where the first argument is a void*
// pointing to some block of memory.
// If new memory is allocated, it will then be tracked by asan since
// rtl functions are intercepted
#define CHECK_AND_CALL(allocationCheck, functionPointer, asanFunction, ptr, \
                       ...)                                                 \
  do {                                                                      \
    if (!asan_mz_size(ptr) && allocationCheck(ptr)) {                                             \
      return functionPointer(ptr, __VA_ARGS__);                             \
    } else                                                                  \
      return asanFunction(ptr, __VA_ARGS__);                                \
  } while (0)

// If memory is freed, we need to remove system allocation map
// tracking.
#define CHECK_AND_CALL_FREE(allocationCheck, functionPointer, asanFunction, \
                            ptr, ...)                                       \
  do {                                                                      \
    if (!asan_mz_size(ptr) && allocationCheck(ptr)) {                                             \
      functionPointer(ptr, __VA_ARGS__);                                    \
      RemoveFromSystemHeapAllocationsMap(ptr);                              \
    } else                                                                  \
      return asanFunction(ptr, __VA_ARGS__);                                \
  } while (0)

// In cases where the allocation took place prior to asan initialization
// asan will need to transition ownership of the memory to itself
// because of the rtl function overrides. After asan assumes ownership,
// we can continue through the normal asan callstack for functions
// that manipulate memory
// i.e. Asan does an allocation and then copies previous contents to new asan
// memory
// Different versions of free need to be used depending on if a debug
// version of a crt function is called or if an aligned crt function is called
#define SWITCH_TO_ASAN_ALLOCATION(allocationCheck, sizeCheck, asanFunction, \
                                  freeFn, ptr, ...)                         \
  do {                                                                      \
    if (!asan_mz_size(ptr) && allocationCheck(ptr)) {                           \
      auto __asanAllocation = asanFunction(nullptr, __VA_ARGS__);           \
      REAL(memcpy)(__asanAllocation, ptr, sizeCheck);                       \
      freeFn;                                                               \
      return __asanAllocation;                                              \
    } else                                                                  \
      return asanFunction(ptr, __VA_ARGS__);                                \
  } while (0)

template <typename Runtime>
struct __RuntimeFunctions {
  static inline void (*pAlignedFree)(void *);
  static inline size_t (*pAlignedMsize)(void *, size_t, size_t);
  static inline void *(*pAlignedOffsetRealloc)(void *, size_t, size_t, size_t);
  static inline void *(*pAlignedOffsetRecalloc)(void *, size_t, size_t, size_t,
                                                size_t);
  static inline void *(*pAlignedRealloc)(void *, size_t, size_t);
  static inline void *(*pAlignedRecalloc)(void *, size_t, size_t, size_t);
  static inline void *(*pCallocBase)(size_t, size_t);
  static inline void *(*pCallocCrt)(size_t, size_t);
  static inline void *(*pExpand)(void *, size_t);
  static inline void *(*pExpandBase)(void *, size_t);
  static inline void (*pFreeBase)(void *);
  static inline size_t (*pMsize)(void *);
  static inline size_t (*pMsizeBase)(void *);
  static inline void *(*pRealloc)(void *, size_t);
  static inline void *(*pReallocBase)(void *, size_t);
  static inline void *(*pReallocCrt)(void *, size_t);
  static inline void *(*pRecalloc)(void *, size_t, size_t);
  static inline void *(*pRecallocBase)(void *, size_t, size_t);
  static inline void *(*pRecallocCrt)(void *, size_t, size_t);
  static inline void *(*pCalloc)(size_t, size_t);
  static inline void (*pFree)(void *);

#if defined(_DEBUG)
  static inline void (*pAlignedFreeDbg)(void *);
  static inline void *(*pReallocDbg)(void *, size_t, int, const char *, int);
  static inline void *(*pAlignedOffsetReallocDbg)(void *const, size_t, size_t,
                                                  size_t, char const *, int);
  static inline void *(*pAlignedOffsetRecallocDbg)(void *const, size_t, size_t,
                                                   size_t, size_t, char const *,
                                                   int);
  static inline void *(*pAlignedReallocDbg)(void *const, size_t, size_t,
                                            char const *, int);
  static inline void *(*pAlignedRecallocDbg)(void *const, size_t, size_t,
                                             size_t, char const *, int);
  static inline void *(*pCallocDbg)(size_t, size_t, int, const char *, int);
  static inline void *(*pExpandDbg)(void *, size_t, int, const char *, int);
  static inline void (*pFreeDbg)(void *, int);
  static inline size_t (*pMsizeDbg)(void *, int);
  static inline void *(*pRecallocDbg)(void *, size_t, size_t, int, const char *,
                                      int);
#endif

  static inline void AlignedFree(void *ptr) {
    CHECK_AND_CALL_FREE(AlignedAllocatedPriorToAsanInit, pAlignedFree,
                        ::_aligned_free, ptr);
  }

  static inline size_t AlignedMsize(void *ptr, size_t alignment,
                                    size_t offset) {
    CHECK_AND_CALL(AlignedAllocatedPriorToAsanInit, pAlignedMsize,
                   ::_aligned_msize, ptr, alignment, offset);
  }

  static inline void *AlignedOffsetRealloc(void *ptr, size_t size,
                                           size_t alignment, size_t offset) {
    SWITCH_TO_ASAN_ALLOCATION(AlignedAllocatedPriorToAsanInit,
                              pAlignedMsize(ptr, alignment, offset),
                              ::_aligned_offset_realloc, AlignedFree(ptr), ptr,
                              size, alignment, offset);
  }

  static inline void *AlignedOffsetRecalloc(void *ptr, size_t num,
                                            size_t element_size,
                                            size_t alignment, size_t offset) {
    SWITCH_TO_ASAN_ALLOCATION(AlignedAllocatedPriorToAsanInit,
                              pAlignedMsize(ptr, alignment, offset),
                              ::_aligned_offset_recalloc, AlignedFree(ptr), ptr,
                              num, element_size, alignment, offset);
  }

  static inline void *AlignedRealloc(void *ptr, size_t size, size_t alignment) {
    SWITCH_TO_ASAN_ALLOCATION(
        AlignedAllocatedPriorToAsanInit, pAlignedMsize(ptr, alignment, 0),
        ::_aligned_realloc, AlignedFree(ptr), ptr, size, alignment);
  }

  static inline void *AlignedRecalloc(void *ptr, size_t num,
                                      size_t element_size, size_t alignment) {
    SWITCH_TO_ASAN_ALLOCATION(AlignedAllocatedPriorToAsanInit,
                              pAlignedMsize(ptr, alignment, 0),
                              ::_aligned_recalloc, AlignedFree(ptr), ptr, num,
                              element_size, alignment);
  }

  static inline void *Expand(void *ptr, size_t size) {
    CHECK_AND_CALL(AllocatedPriorToAsanInit, pExpand, ::_expand, ptr, size);
  }

  static inline void *ExpandBase(void *ptr, size_t size) {
    CHECK_AND_CALL(AllocatedPriorToAsanInit, pExpandBase, ::_expand, ptr, size);
  }

  static inline void FreeBase(void *ptr) {
    CHECK_AND_CALL_FREE(AllocatedPriorToAsanInit, pFreeBase, ::free, ptr);
  }

  static inline size_t Msize(void *ptr) {
    CHECK_AND_CALL(AllocatedPriorToAsanInit, pMsize, ::_msize, ptr);
  }

  static inline size_t MsizeBase(void *ptr) {
    CHECK_AND_CALL(AllocatedPriorToAsanInit, pMsizeBase, ::_msize_base, ptr);
  }

  static inline void *Realloc(void *ptr, size_t size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr), ::realloc,
                              Free(ptr), ptr, size);
  }

  static inline void *ReallocBase(void *ptr, size_t size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr),
                              ::_realloc_base, Free(ptr), ptr, size);
  }

  static inline void *ReallocCrt(void *ptr, size_t size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr), ::realloc,
                              Free(ptr), ptr, size);
  }

  static inline void *RecallocBase(void *ptr, size_t num, size_t elem_size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr),
                              ::_recalloc_base, Free(ptr), ptr, num, elem_size);
  }

  static inline void *Recalloc(void *ptr, size_t num, size_t elem_size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr),
                              ::_recalloc, Free(ptr), ptr, num, elem_size);
  }

  static inline void *RecallocCrt(void *ptr, size_t num, size_t elem_size) {
    SWITCH_TO_ASAN_ALLOCATION(AllocatedPriorToAsanInit, pMsize(ptr),
                              ::_recalloc, Free(ptr), ptr, num, elem_size);
  }

  static inline void Free(void *ptr) {
    CHECK_AND_CALL_FREE(AllocatedPriorToAsanInit, pFree, ::free, ptr);
  }

#ifdef _DEBUG
  static inline void AlignedFreeDbg(void *const ptr) {
    CHECK_AND_CALL_FREE(DbgAlignedAllocatedPriorToAsanInit, pAlignedFreeDbg,
                        ::_aligned_free_dbg, ptr);
  }

  static inline void *AlignedOffsetReallocDbg(
      void *const ptr, size_t const size, size_t const alignment,
      size_t const offset, char const *const fileName, int const lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(
        DbgAlignedAllocatedPriorToAsanInit, pMsizeDbg(ptr, _NORMAL_BLOCK),
        ::_aligned_offset_realloc_dbg, AlignedFreeDbg(ptr), ptr, size,
        alignment, offset, fileName, lineNumber);
  }

  static inline void *AlignedOffsetRecallocDbg(
      void *const ptr, size_t const num, size_t const element_size,
      size_t const alignment, size_t const offset, char const *const fileName,
      int const lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(
        DbgAlignedAllocatedPriorToAsanInit, pMsizeDbg(ptr, _NORMAL_BLOCK),
        ::_aligned_offset_recalloc_dbg, AlignedFreeDbg(ptr), ptr, num,
        element_size, alignment, offset, fileName, lineNumber);
  }

  static inline void *AlignedReallocDbg(void *const ptr, size_t const size,
                                        size_t const alignment,
                                        char const *const fileName,
                                        int const lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(DbgAlignedAllocatedPriorToAsanInit,
                              pMsizeDbg(ptr, _NORMAL_BLOCK),
                              ::_aligned_realloc_dbg, AlignedFreeDbg(ptr), ptr,
                              size, alignment, fileName, lineNumber);
  }

  static inline void *AlignedRecallocDbg(void *const ptr, size_t const num,
                                         size_t const size,
                                         size_t const alignment,
                                         char const *const fileName,
                                         int const lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(DbgAlignedAllocatedPriorToAsanInit,
                              pMsizeDbg(ptr, _NORMAL_BLOCK),
                              ::_aligned_recalloc_dbg, AlignedFreeDbg(ptr), ptr,
                              num, size, alignment, fileName, lineNumber);
  }

  static inline void *ExpandDbg(void *ptr, size_t size, int blockType,
                                const char *fileName, int lineNumber) {
    CHECK_AND_CALL(DbgAllocatedPriorToAsanInit, pExpandDbg, ::_expand_dbg, ptr,
                   size, blockType, fileName, lineNumber);
  }

  static inline void FreeDbg(void *ptr, int blockType) {
    CHECK_AND_CALL_FREE(DbgAllocatedPriorToAsanInit, pFreeDbg, ::_free_dbg, ptr,
                        blockType);
  }

  static inline size_t MsizeDbg(void *ptr, int blockType) {
    CHECK_AND_CALL(DbgAllocatedPriorToAsanInit, pMsizeDbg, ::_msize_dbg, ptr,
                   blockType);
  }

  static inline void *ReallocDbg(void *ptr, size_t size, int blockType,
                                 const char *fileName, int lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(DbgAllocatedPriorToAsanInit,
                              pMsizeDbg(ptr, _NORMAL_BLOCK), ::_realloc_dbg,
                              FreeDbg(ptr, blockType), ptr, size, blockType,
                              fileName, lineNumber);
  }

  static inline void *RecallocDbg(void *ptr, size_t num, size_t size,
                                  int blockType, const char *fileName,
                                  int lineNumber) {
    SWITCH_TO_ASAN_ALLOCATION(DbgAllocatedPriorToAsanInit,
                              pMsizeDbg(ptr, _NORMAL_BLOCK), ::_recalloc_dbg,
                              FreeDbg(ptr, blockType), ptr, num, size,
                              blockType, fileName, lineNumber);
  }

#endif

  struct OverrideFunctionInfo {
    const char *Name;
    uptr NewFunction;
    uptr *OldFunction;
  };

  static void OverrideFunctions(const char *dllName) {
    static const OverrideFunctionInfo functions[] = {
#ifdef _DEBUG
        {"_aligned_free_dbg", reinterpret_cast<uptr>(&AlignedFreeDbg),
         reinterpret_cast<uptr *>(&pAlignedFreeDbg)},
        {"_aligned_offset_recalloc_dbg",
         reinterpret_cast<uptr>(&AlignedOffsetRecallocDbg),
         reinterpret_cast<uptr *>(&pAlignedOffsetRecallocDbg)},
        {"_aligned_realloc_dbg", reinterpret_cast<uptr>(&AlignedReallocDbg),
         reinterpret_cast<uptr *>(&pAlignedReallocDbg)},
        {"_aligned_recalloc_dbg", reinterpret_cast<uptr>(&AlignedRecallocDbg),
         reinterpret_cast<uptr *>(&pAlignedRecallocDbg)},
        {"_expand_dbg", reinterpret_cast<uptr>(&ExpandDbg),
         reinterpret_cast<uptr *>(&pExpandDbg)},
        {"_free_dbg", reinterpret_cast<uptr>(&FreeDbg),
         reinterpret_cast<uptr *>(&pFreeDbg)},
        {"_msize_dbg", reinterpret_cast<uptr>(&MsizeDbg),
         reinterpret_cast<uptr *>(&pMsizeDbg)},
        {"_realloc_dbg", reinterpret_cast<uptr>(&ReallocDbg),
         reinterpret_cast<uptr *>(&pReallocDbg)},
        {"_recalloc_dbg", reinterpret_cast<uptr>(&RecallocDbg),
         reinterpret_cast<uptr *>(&pRecallocDbg)},
#endif
        {"_aligned_free", reinterpret_cast<uptr>(&AlignedFree),
         reinterpret_cast<uptr *>(&pAlignedFree)},
        {"_aligned_msize", reinterpret_cast<uptr>(&AlignedMsize),
         reinterpret_cast<uptr *>(&pAlignedMsize)},
        {"_aligned_offset_realloc",
         reinterpret_cast<uptr>(&AlignedOffsetRealloc),
         reinterpret_cast<uptr *>(pAlignedOffsetRealloc)},
        {"_aligned_offset_recalloc",
         reinterpret_cast<uptr>(&AlignedOffsetRecalloc),
         reinterpret_cast<uptr *>(&pAlignedOffsetRecalloc)},
        {"_aligned_realloc", reinterpret_cast<uptr>(&AlignedRealloc),
         reinterpret_cast<uptr *>(&pAlignedRealloc)},
        {"_aligned_recalloc", reinterpret_cast<uptr>(&AlignedRecalloc),
         reinterpret_cast<uptr *>(&pAlignedRecalloc)},
        {"_expand", reinterpret_cast<uptr>(&Expand),
         reinterpret_cast<uptr *>(&pExpand)},
        {"_expand_base", reinterpret_cast<uptr>(&ExpandBase),
         reinterpret_cast<uptr *>(&pExpandBase)},
        {"_free_base", reinterpret_cast<uptr>(&FreeBase),
         reinterpret_cast<uptr *>(&pFreeBase)},
        {"_msize", reinterpret_cast<uptr>(&Msize),
         reinterpret_cast<uptr *>(&pMsize)},
        {"_msize_base", reinterpret_cast<uptr>(&MsizeBase),
         reinterpret_cast<uptr *>(&pMsizeBase)},
        {"realloc", reinterpret_cast<uptr>(&Realloc),
         reinterpret_cast<uptr *>(&pRealloc)},
        {"_realloc_base", reinterpret_cast<uptr>(&ReallocBase),
         reinterpret_cast<uptr *>(&pReallocBase)},
        {"_realloc_crt", reinterpret_cast<uptr>(&ReallocCrt),
         reinterpret_cast<uptr *>(&pReallocCrt)},
        {"_recalloc", reinterpret_cast<uptr>(&Recalloc),
         reinterpret_cast<uptr *>(&pRecalloc)},
        {"_recalloc_base", reinterpret_cast<uptr>(&RecallocBase),
         reinterpret_cast<uptr *>(&pRecallocBase)},
        {"_recalloc_crt", reinterpret_cast<uptr>(&RecallocCrt),
         reinterpret_cast<uptr *>(&pRecallocCrt)},
        {"free", reinterpret_cast<uptr>(&Free),
         reinterpret_cast<uptr *>(&pFree)}};

    for (auto &[name, newFunction, oldFunction] : functions) {
      if (!__interception::OverrideFunction(name, newFunction, oldFunction,
                                            dllName)) {
        VPrintf(2, "Failed to override function %s in %s\n", name, dllName);
      }
    }
  }
};

// Below are the runtimes that contain either a full set or subset of the
// runtime functions that are attempted to be hooked from above.

// Overrides functions in "msvcr100(d).dll"
struct Msvcr100 {
  Msvcr100() {
#ifdef _DEBUG
    const char *dllName = "msvcr100d.dll";
#else
    const char *dllName = "msvcr100.dll";
#endif
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Msvcr100> runtime;
};

// Overrides functions in "msvcr110(d).dll"
struct Msvcr110 {
  Msvcr110() {
#ifdef _DEBUG
    const char *dllName = "msvcr110d.dll";
#else
    const char *dllName = "msvcr110.dll";
#endif
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Msvcr110> runtime;
};

// Overrides functions in "msvcr120(d).dll"
struct Msvcr120 {
  Msvcr120() {
#ifdef _DEBUG
    const char *dllName = "msvcr120d.dll";
#else
    const char *dllName = "msvcr120.dll";
#endif
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Msvcr120> runtime;
};

// Overrides functions in "vcruntime140(d).dll"
struct Vcruntime140 {
  Vcruntime140() {
#ifdef _DEBUG
    const char *dllName = "vcruntime140d.dll";
#else
    const char *dllName = "vcruntime140.dll";
#endif
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Vcruntime140> runtime;
};

// Overrides functions in "ucrtbase(d).dll"
struct Ucrtbase {
  Ucrtbase() {
#ifdef _DEBUG
    const char *dllName = "ucrtbased.dll";
#else
    const char *dllName = "ucrtbase.dll";
#endif
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Ucrtbase> runtime;
};

// Overrides functions in "ntdll.dll"
struct Ntdll {
  Ntdll() {
    const char *dllName = "ntdll.dll";
    runtime.OverrideFunctions(dllName);
  }

  static __RuntimeFunctions<Ntdll> runtime;
};

void OverrideFunctionsForEachCrt() {
  // static instances of specific runtimes to keep track of functions to
  // delegate back to in case there are allocations that happened prior to the
  // asan runtime initialization in them
  static Msvcr100 msvcr100;
  static Msvcr110 msvcr110;
  static Msvcr120 msvcr120;
  static Vcruntime140 vcruntime140;
  static Ntdll ntdll;
  static Ucrtbase ucrtBase;
}

}  // namespace __asan
#endif