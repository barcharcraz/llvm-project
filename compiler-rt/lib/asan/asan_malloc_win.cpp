//===-- asan_malloc_win.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// ASAN versions of the C Runtime allocation API used on Windows, including
// interception of Rtl* Win32 APIs.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS
#include <stddef.h>

#include "asan_allocator.h"
#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_malloc_win_moveable.h"
#include "asan_stack.h"
#include "asan_win_runtime_functions.h"
#include "asan_win_scoped_lock.h"
#include "asan_win_thunk_common.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_win.h"
#include "sanitizer_common/sanitizer_win_immortalize.h"

// Intentionally not including windows.h here, to avoid the risk of
// pulling in conflicting declarations of these functions. (With mingw-w64,
// there's a risk of windows.h pulling in stdint.h.)
typedef void *HANDLE, *LPVOID, *PHANDLE, *HGLOBAL, *HLOCAL, *HWND;
typedef const void *LPCVOID;
typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned long DWORD, LOGICAL;

struct _RTL_HEAP_PARAMETERS;
typedef _RTL_HEAP_PARAMETERS *PRTL_HEAP_PARAMETERS;

using __sanitizer::uptr;

constexpr unsigned long LOW_FRAG_HEAP_SIGNATURE = 0xFFEEFFEE;

constexpr unsigned long HEAP_NO_SERIALIZE = 0x00000001;
constexpr unsigned long HEAP_GENERATE_EXCEPTIONS = 0x00000004;
constexpr unsigned long HEAP_ZERO_MEMORY = 0x00000008;
constexpr unsigned long HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
constexpr unsigned long HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;
constexpr unsigned long HEAP_NO_CACHE_BLOCK = 0x00800000;

constexpr unsigned long HEAP_ALLOCATE_SUPPORTED_FLAGS =
    (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_ALLOCATE_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);

constexpr unsigned long HEAP_REALLOC_SUPPORTED_FLAGS =
    (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_REALLOC_UNSUPPORTED_FLAGS =
    (~HEAP_REALLOC_SUPPORTED_FLAGS);

constexpr unsigned long HEAP_MAXIMUM_TAG = 0x0FFF;
constexpr unsigned long HEAP_TAG_MASK = HEAP_MAXIMUM_TAG << 18;

extern "C" {
HANDLE WINAPI GetProcessHeap();
DWORD WINAPI GetCurrentThreadId();
BOOL WINAPI HeapLock(HANDLE);
BOOL WINAPI HeapUnlock(HANDLE);

// TODO: Bug #1514368
// We should add logic to interceptors and allocators to decorate allocations
// so when a mismatched free is called (e.g. GlobalAlloc allocation with free or
// anything besides GlobalFree) we should report an error back to the user
// regarding the mismatch.
_declspec(dllimport) HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HGLOBAL WINAPI GlobalFree(HGLOBAL hMem);
_declspec(dllimport) SIZE_T WINAPI GlobalSize(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI
    GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
_declspec(dllimport) HGLOBAL WINAPI GlobalLock(HGLOBAL hMem);
_declspec(dllimport) BOOL WINAPI GlobalUnlock(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalHandle(HGLOBAL hMem);
_declspec(dllimport) UINT WINAPI GlobalFlags(HGLOBAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HLOCAL WINAPI LocalFree(HLOCAL hMem);
_declspec(dllimport) SIZE_T WINAPI LocalSize(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI
    LocalReAlloc(HLOCAL hMem, size_t dwBytes, UINT uFlags);
_declspec(dllimport) HLOCAL WINAPI LocalLock(HLOCAL hMem);
_declspec(dllimport) BOOL WINAPI LocalUnlock(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalHandle(HLOCAL hMem);
_declspec(dllimport) UINT WINAPI LocalFlags(HLOCAL hMem);
}

using namespace __asan;

namespace __asan_malloc_impl {
// Common implementation for CRT allocation functions.
size_t msize(void *ptr, const uptr pc, const uptr bp) {
  return asan_malloc_usable_size(ptr, pc, bp);
}

void free(void *ptr, BufferedStackTrace *stack) {
  return asan_free(ptr, stack, FROM_MALLOC);
}

void *malloc(const size_t size, BufferedStackTrace *stack) {
  return asan_malloc(size, stack);
}

void *calloc(const size_t nmemb, const size_t size, BufferedStackTrace *stack) {
  return asan_calloc(nmemb, size, stack);
}

void *realloc(void *ptr, const size_t size, BufferedStackTrace *stack) {
  if (!flags()->allocator_frees_and_returns_null_on_realloc_zero) {
    Report(
        "WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to "
        "FALSE."
        " This is not consistent with libcmt/ucrt/msvcrt behavior.\n");
  }
  return asan_realloc(ptr, size, stack);
}

void *recalloc(void *ptr, const size_t nmemb, const size_t size,
               BufferedStackTrace *stack) {
  if (!flags()->allocator_frees_and_returns_null_on_realloc_zero) {
    Report(
        "WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to "
        "FALSE."
        " This is not consistent with libcmt/ucrt/msvcrt behavior.\n");
  }
  return asan_recalloc(ptr, nmemb, size, stack);
}

void *aligned_malloc(const size_t size, const size_t alignment,
                     BufferedStackTrace *stack) {
  return asan_memalign(alignment, size, stack, FROM_MALLOC);
}

void aligned_free(void *memblock, BufferedStackTrace *stack) {
  asan_free(memblock, stack, FROM_MALLOC);
}

void *aligned_realloc(void *memblock, const size_t size, const size_t alignment,
                      BufferedStackTrace *stack, const uptr pc, const uptr bp) {
  if (size == 0 && memblock != nullptr) {
    asan_free(memblock, stack, FROM_MALLOC);
    return nullptr;
  }

  void *new_ptr = asan_memalign(alignment, size, stack, FROM_MALLOC);
  if (new_ptr && memblock) {
    const size_t aligned_size = asan_malloc_usable_size(memblock, pc, bp);
    internal_memcpy(new_ptr, memblock, Min<size_t>(aligned_size, size));
    asan_free(memblock, stack, FROM_MALLOC);
  }

  return new_ptr;
}

void *aligned_recalloc(void *memblock, const size_t num,
                       const size_t element_size, const size_t alignment,
                       BufferedStackTrace *stack, const uptr pc,
                       const uptr bp) {
  const size_t size = num * element_size;
  const size_t old_size =
      (memblock) ? asan_malloc_usable_size(memblock, pc, bp) : 0;
  void *new_ptr = aligned_realloc(memblock, size, alignment, stack, pc, bp);
  if (new_ptr && old_size < size) {
    REAL(memset)(static_cast<u8 *>(new_ptr) + old_size, 0, size - old_size);
  }
  return new_ptr;
}
}  // namespace __asan_malloc_impl

#define GET_STACK_TRACE_OVER_BOUNDARY(data)                               \
  GET_STACK_TRACE_EXPLICIT(__asan::GetMallocContextSize(),                \
                           __asan::common_flags()->fast_unwind_on_malloc, \
                           (data)->pc, (data)->bp, (data)->caller_pc,     \
                           (data)->extra_context)

// Attribute for functions that will be exported.
#define MALLOC_DLL_EXPORT __declspec(dllexport)

// Attribute for functions that serve the ASAN DLL itself. Noinline to preserve
// stack traces
#define MALLOC_INTERNAL_DEF __declspec(noinline)

extern "C" {
// _msize
MALLOC_DLL_EXPORT size_t __asan_msize(void *ptr, const uptr pc, const uptr bp) {
  return __asan_malloc_impl::msize(ptr, pc, bp);
}

MALLOC_INTERNAL_DEF size_t _msize(void *ptr) {
  GET_CURRENT_PC_BP;
  return __asan_malloc_impl::msize(ptr, pc, bp);
}

MALLOC_INTERNAL_DEF size_t _msize_base(void *ptr) {
  GET_CURRENT_PC_BP;
  return __asan_malloc_impl::msize(ptr, pc, bp);
}

MALLOC_INTERNAL_DEF size_t _msize_dbg(void *ptr, int) {
  GET_CURRENT_PC_BP;
  return __asan_malloc_impl::msize(ptr, pc, bp);
}

// free
MALLOC_DLL_EXPORT void __cdecl __asan_free(__asan_win_stack_data *data,
                                           void *ptr) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  __asan_malloc_impl::free(ptr, &stack);
}

MALLOC_INTERNAL_DEF void free(void *ptr) {
  GET_STACK_TRACE_FREE;
  return __asan_malloc_impl::free(ptr, &stack);
}

MALLOC_INTERNAL_DEF void _free_base(void *ptr) {
  GET_STACK_TRACE_FREE;
  return __asan_malloc_impl::free(ptr, &stack);
}

MALLOC_INTERNAL_DEF void _free_dbg(void *ptr, int) {
  GET_STACK_TRACE_FREE;
  return __asan_malloc_impl::free(ptr, &stack);
}

// malloc
MALLOC_DLL_EXPORT void *__cdecl __asan_malloc(__asan_win_stack_data *data,
                                              const size_t size) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::malloc(size, &stack);
}

MALLOC_INTERNAL_DEF void *malloc(const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::malloc(size, &stack);
}

MALLOC_INTERNAL_DEF void *_malloc_base(const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::malloc(size, &stack);
}

MALLOC_INTERNAL_DEF void *_malloc_dbg(const size_t size, int, const char *,
                                      int) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::malloc(size, &stack);
}

// calloc
MALLOC_DLL_EXPORT void *__cdecl __asan_calloc(__asan_win_stack_data *data,
                                              size_t const nmemb,
                                              size_t const size) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::calloc(nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *calloc(const size_t nmemb, const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::calloc(nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_calloc_base(const size_t nmemb, const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::calloc(nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_calloc_impl(const size_t nmemb, const size_t size,
                                       int *errno_tmp) {
  // Provided by legacy msvcrt.
  (void)errno_tmp;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::calloc(nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_calloc_dbg(const size_t nmemb, const size_t size,
                                      int, const char *, int) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::calloc(nmemb, size, &stack);
}

// realloc
MALLOC_DLL_EXPORT void *__cdecl __asan_realloc(__asan_win_stack_data *data,
                                               void *ptr, const size_t size) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::realloc(ptr, size, &stack);
}

MALLOC_INTERNAL_DEF void *realloc(void *ptr, const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::realloc(ptr, size, &stack);
}

MALLOC_INTERNAL_DEF void *_realloc_base(void *ptr, const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::realloc(ptr, size, &stack);
}

MALLOC_INTERNAL_DEF void *_realloc_dbg(void *ptr, const size_t size, int,
                                       const char *, int) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::realloc(ptr, size, &stack);
}

// recalloc
MALLOC_DLL_EXPORT void *__cdecl __asan_recalloc(__asan_win_stack_data *data,
                                                void *ptr, const size_t nmemb,
                                                const size_t size) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::recalloc(ptr, nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_recalloc(void *ptr, const size_t nmemb,
                                    const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::recalloc(ptr, nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_recalloc_base(void *ptr, const size_t nmemb,
                                         const size_t size) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::recalloc(ptr, nmemb, size, &stack);
}

MALLOC_INTERNAL_DEF void *_recalloc_dbg(void *ptr, const size_t nmemb,
                                        const size_t size, int, const char *,
                                        int) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::recalloc(ptr, nmemb, size, &stack);
}

// expand
MALLOC_INTERNAL_DEF void *_expand(void *, size_t) {
  // _expand is used in realloc-like functions to resize the buffer if possible.
  // We don't want memory to stand still while resizing buffers, so return 0.
  return nullptr;
}

MALLOC_INTERNAL_DEF void *_expand_dbg(void *, size_t, int, const char *, int) {
  return nullptr;
}

// aligned_msize
MALLOC_INTERNAL_DEF size_t _aligned_msize(void *memblock,
                                          const size_t alignment,
                                          const size_t offset) {
  // Same impl as non-aligned.
  (void)alignment;
  (void)offset;
  GET_CURRENT_PC_BP;
  return __asan_malloc_impl::msize(memblock, pc, bp);
}

MALLOC_INTERNAL_DEF size_t _aligned_msize_dbg(void *memblock,
                                              const size_t alignment,
                                              const size_t offset) {
  // Same impl as non-aligned.
  (void)alignment;
  (void)offset;
  GET_CURRENT_PC_BP;
  return __asan_malloc_impl::msize(memblock, pc, bp);
}

// aligned_malloc
MALLOC_DLL_EXPORT void *__cdecl __asan_aligned_malloc(
    __asan_win_stack_data *data, const size_t size, const size_t alignment) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::aligned_malloc(size, alignment, &stack);
}

MALLOC_INTERNAL_DEF void *_aligned_malloc(const size_t size,
                                          const size_t alignment) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_malloc(size, alignment, &stack);
}

MALLOC_INTERNAL_DEF void *_aligned_malloc_dbg(const size_t size,
                                              const size_t alignment,
                                              char const *, int) {
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_malloc(size, alignment, &stack);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_malloc(const size_t size,
                                                 const size_t alignment,
                                                 const size_t offset) {
  // We don't respect the offset
  (void)offset;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_malloc(size, alignment, &stack);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_malloc_dbg(const size_t size,
                                                     const size_t alignment,
                                                     const size_t offset,
                                                     char const *, int) {
  // We don't respect the offset
  (void)offset;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_malloc(size, alignment, &stack);
}

// aligned_free
MALLOC_DLL_EXPORT void __cdecl __asan_aligned_free(__asan_win_stack_data *data,
                                                   void *memblock) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  __asan_malloc_impl::aligned_free(memblock, &stack);
}

MALLOC_INTERNAL_DEF void _aligned_free(void *memblock) {
  GET_STACK_TRACE_MALLOC;
  __asan_malloc_impl::aligned_free(memblock, &stack);
}

MALLOC_INTERNAL_DEF void _aligned_free_dbg(void *memblock) {
  GET_STACK_TRACE_MALLOC;
  __asan_malloc_impl::aligned_free(memblock, &stack);
}

// aligned_realloc
MALLOC_DLL_EXPORT void *__cdecl __asan_aligned_realloc(
    __asan_win_stack_data *data, void *memblock, const size_t size,
    const size_t alignment) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::aligned_realloc(memblock, size, alignment, &stack,
                                             data->pc, data->bp);
}

MALLOC_INTERNAL_DEF void *_aligned_realloc(void *memblock, const size_t size,
                                           const size_t alignment) {
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_realloc(memblock, size, alignment, &stack,
                                             pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_realloc_dbg(void *memblock,
                                               const size_t size,
                                               const size_t alignment,
                                               char const *, int) {
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_realloc(memblock, size, alignment, &stack,
                                             pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_realloc(void *memblock,
                                                  const size_t size,
                                                  const size_t alignment,
                                                  const size_t offset) {
  // We don't respect the offset
  (void)offset;
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_realloc(memblock, size, alignment, &stack,
                                             pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_realloc_dbg(void *memblock,
                                                      const size_t size,
                                                      const size_t alignment,
                                                      const size_t offset,
                                                      char const *, int) {
  // We don't respect the offset
  (void)offset;
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_realloc(memblock, size, alignment, &stack,
                                             pc, bp);
}

// aligned_recalloc
MALLOC_DLL_EXPORT void *__cdecl __asan_aligned_recalloc(
    __asan_win_stack_data *data, void *memblock, const size_t num,
    const size_t element_size, const size_t alignment) {
  GET_STACK_TRACE_OVER_BOUNDARY(data);
  return __asan_malloc_impl::aligned_recalloc(
      memblock, num, element_size, alignment, &stack, data->pc, data->bp);
}

MALLOC_INTERNAL_DEF void *_aligned_recalloc(void *memblock, const size_t num,
                                            const size_t element_size,
                                            const size_t alignment) {
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_recalloc(memblock, num, element_size,
                                              alignment, &stack, pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_recalloc_dbg(void *memblock,
                                                const size_t num,
                                                const size_t element_size,
                                                const size_t alignment,
                                                char const *, int) {
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_recalloc(memblock, num, element_size,
                                              alignment, &stack, pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_recalloc(void *memblock,
                                                   const size_t num,
                                                   const size_t element_size,
                                                   const size_t alignment,
                                                   const size_t offset) {
  // We don't respect the offset
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_recalloc(memblock, num, element_size,
                                              alignment, &stack, pc, bp);
}

MALLOC_INTERNAL_DEF void *_aligned_offset_recalloc_dbg(
    void *memblock, const size_t num, const size_t element_size,
    const size_t alignment, const size_t offset, char const *, int) {
  // We don't respect the offset
  GET_CURRENT_PC_BP;
  GET_STACK_TRACE_MALLOC;
  return __asan_malloc_impl::aligned_recalloc(memblock, num, element_size,
                                              alignment, &stack, pc, bp);
}

// We need to provide symbols for all the debug CRT functions if we decide to
// provide any. Most of these functions make no sense under ASan and so we
// make them no-ops.
long _CrtSetBreakAlloc(long const) { return ~0; }

void _CrtSetDbgBlockType(void *const, int const) { return; }

typedef int(__cdecl *CRT_ALLOC_HOOK)(int, void *, size_t, int, long,
                                     const unsigned char *, int);

CRT_ALLOC_HOOK _CrtGetAllocHook() { return nullptr; }

CRT_ALLOC_HOOK _CrtSetAllocHook(CRT_ALLOC_HOOK const hook) { return hook; }

int _CrtCheckMemory() { return 1; }

int _CrtSetDbgFlag(int const new_bits) { return new_bits; }

typedef void (*CrtDoForAllClientObjectsCallback)(void *, void *);

void _CrtDoForAllClientObjects(CrtDoForAllClientObjectsCallback const,
                               void *const) {
  return;
}

int _CrtIsValidPointer(void const *p, unsigned int const, int const) {
  return p != nullptr;
}

int _CrtIsValidHeapPointer(void const *block) {
  if (!block) {
    return 0;
  }

  return __sanitizer_get_ownership(block);
}

int _CrtIsMemoryBlock(void const *const, unsigned const, long *const,
                      char **const, int *const) {
  return 0;
}

int _CrtReportBlockType(void const *const) { return -1; }

typedef void(__cdecl *CRT_DUMP_CLIENT)(void *, size_t);

CRT_DUMP_CLIENT _CrtGetDumpClient() { return nullptr; }

CRT_DUMP_CLIENT _CrtSetDumpClient(CRT_DUMP_CLIENT new_client) {
  return new_client;
}

void _CrtMemCheckpoint(void *const) { return; }

int _CrtMemDifference(void *const, void const *const, void const *const) {
  return 0;
}

void _CrtMemDumpAllObjectsSince(void const *const) { return; }

int _CrtDumpMemoryLeaks() { return 0; }

void _CrtMemDumpStatistics(void const *const) { return; }

int _crtDbgFlag{0};
long _crtBreakAlloc{-1};
CRT_DUMP_CLIENT _pfnDumpClient{nullptr};

int *__p__crtDbgFlag() { return &_crtDbgFlag; }

long *__p__crtBreakAlloc() { return &_crtBreakAlloc; }

// TODO: These were added upstream but conflict with definitions in ucrtbased.
// int _CrtDbgReport(int, const char *, int, const char *, const char *, ...) {
//   ShowStatsAndAbort();
// }
//
// int _CrtDbgReportW(int reportType, const wchar_t *, int, const wchar_t *,
//                    const wchar_t *, ...) {
//   ShowStatsAndAbort();
// }
//
// int _CrtSetReportMode(int, int) { return 0; }

}  // extern "C"

struct AsanHeapMemoryNode {
  static void *operator new(size_t size,
                            InternalAllocatorCache *allocation_cache) {
    return InternalAlloc(size, allocation_cache);
  }
  static void operator delete(void *p,
                              InternalAllocatorCache *allocation_cache) {
    InternalFree(p, allocation_cache);
  }

  AsanHeapMemoryNode(void *_memory) : memory(_memory) {}

  void *memory;
  AsanHeapMemoryNode *next;
};

// TODO: Primes chosen for hash table size is a guess - can be tweaked.
const uptr AsanMemoryMapSize = 4099;
using AsanMemoryList = __sanitizer::IntrusiveList<AsanHeapMemoryNode>;
using AsanMemoryMap =
    __sanitizer::AddrHashMap<AsanHeapMemoryNode *, AsanMemoryMapSize>;

// -- Lock Usage / Multithreaded Behavior Summary --
// During our intercepted versions of the RTL Heap functions, we need to ensure:
// 1. Atomic access when updating the AsanMemoryList and AsanMemoryMap, which
//    are stored in the AsanHeap.
//     - TODO: This can probably be made lock-free in the future.
// 2. Prevent internal allocations of the Low Fragmentation Heap from causing
//    false-positive wild-pointer errors.
// 3. Provide a guarantee that the AsanHeap data structure is not destroyed via
//    RtlDestroyHeap while it is otherwise being used.
//     3.5 And also ensure we don't return data that is invalid if the heap is
//     being destroyed.
//
// To handle 1 & 2, there are two locks:
// 1. MemoryMapLock (see AsanHeap::MemoryMapLockGuard for implementation
//    details)
// 2. RtlReentrancyLock (see AsanHeap::RtlReentrancyLockGuard for implementation
//    details).
//
// To handle 3, we reference count the AsanHeap memory. When using AsanHeap
// data, always use GetAsanHeap/DeleteAsanHeap/AsanHeapHandle to ensure proper
// handling of the reference count. We must actively release the handle prior to
// returning to check whether we should return the allocated data or whether it
// would immediately become invalidated due to the AsanHeapHandle leaving scope.

// There is also a third lock to keep in mind:
// 3. The Win32 Heap Lock (provided via HeapLock/HeapUnlock).

// This is a recursive lock (backed by CRITICAL_SECTION) provided as part of the
// Win32 Heap APIs via the HeapLock and HeapUnlock functions. This lock may be
// taken by the real implementation of any of the Rtl*Heap functions, but it is
// also publicly accessible and may be taken by the user prior to calling any
// Rtl*Heap functions. In addition, it is needed in order to complete a walk of
// the heap via HeapWalk, which we may need to do during AllocationOwnership.

// The unique nature of the Win32 Heap Lock gives us two rules to follow:
// 1. If we ever take the Win32 Heap Lock, it *must* be the first lock we take.
// 2. If we ever call code that may allocate while holding a lock, we *must*
//    also take the Win32 Heap Lock.

// The MemoryMapLock is a fine-grained lock that should only be taken for as
// little time as possible when accessing the memory_map and asan_memory data.
// Locking and unlocking is managed by the MemoryMapLockGuard object.
// We don't need the Win32 Heap Lock to update these data structures, so instead
// we ensure we adhere to the above rules by making sure we never call into
// another function while holding the MemoryMapLock. This is enforced by
// DCHECKs added prior to every call to another Asan function (via
// Debug_AssertLockInvariant_CallAsan), or a real Rtl function (via
// Debug_AssertLockInvariant_CallRtl).

// The RtlReentrancyLock is used in lieu of a better method to track when
// reentrancy occurs in the real RTL Heap function implementation. When using
// the Low Fragmentation Heap (LFH), internal allocations are needed that also
// go through RtlAllocateHeap/RtlFreeHeap. This only happens when using LFH and
// these allocations are marked with a flag HEAP_NO_CACHE_BLOCK upon allocation,
// but upon deallocation cannot be detected via flag, and are filtered out of
// the entries returned by HeapWalk. This lock serves as a way to detect when we
// have called back into the real RTL implementation to handle an allocation or
// deallocation, but must also allocate or deallocate an internal LFH structure.
// Without this tracking, these frees will look like wild pointer errors, since
// we will be unable to find their allocation owner. Because we take this lock
// then call back into the real RTL functions, we must assume that the Win32
// Heap Lock may be taken at some point in the future. Therefore, the Win32 Heap
// Lock must be taken prior (the Win32 Heap Lock is recursive) to acquiring this
// lock to avoid deadlocks. We use a DCHECK added prior to every call into a
// real Rtl function (via Debug_AssertLockInvariant_CallRtl) to ensure we have
// taken both the Win32 Heap Lock and the RtlReentrancyLock. It is permissible
// to call another Asan function while holding these, but it is unnecessary. We
// use a DCHECK prior to every call into an Asan function (via
// Debug_AssertLockInvariant_CallAsan) to ensure this.

// This gives us a strong ordering between locks:
// Win32 Heap Lock > RtlReentrancyLock > MemoryMapLock

// The following are the permitted lock states, never breaking the above
// invariant.

// clang-format off
//                +-----------+
//                | User Code |
//                +--------+--+
//                         |             +------------------+
//                         |             |                  |
//                         v             v                  |
//                      +--+-------------+--+        +------+---------------------------------+
//                      | Win32HeapLock (?) |        |  Call ASAN Functions that may allocate |
//                      | MemoryMapLock ( ) +------->+  ex: asan_malloc                       |
//                      | RtlReentrLock ( ) |        |      WRAP(RtlAllocateHeap)             |
//                      +------+--+--+------+        +----------------------------------------+
//                             ^  ^  ^
//              +--------------+  |  +-------------+
//              |                 |                |
//        IsSystemHeapAddress  +--+         MemoryMapLockGuard
//              |              |                   |
//              |          RtlReentrancyLockGuard  |
//              |              |                   |
//              v              v                   v
// +------------+------+ +-----+-------------+ +---+---------------+
// | Win32HeapLock (L) | | Win32HeapLock (L) | | Win32HeapLock (?) |
// | MemoryMapLock ( ) | | MemoryMapLock ( ) | | MemoryMapLock (L) |
// | RtlReentrLock ( ) | | RtlReentrLock (L) | | RtlReentrLock ( ) |
// +-------------------+ +-----+-------------+ +-------------------+
//                             |
//                             v
//                 +-----------+------------------+
//                 | Call Reentrant RTL Functions |
//                 | ex: REAL(RtlAllocateHeap)    |
//                 +-------------+----------------+
//                               |
//                               |       +------------------+
//                               |       |                  |
//                               v       v                  |
//                      +--------+-------+--+        +------+---------------------------------+
//                      | Win32HeapLock (L) |        |  Call ASAN Functions that may allocate |
//                      | MemoryMapLock ( ) +------->+  ex: asan_malloc                       |
//                      | RtlReentrLock (L) |        |      WRAP(RtlAllocateHeap)             |
//                      +------+--+--+------+        +----------------------------------------+
//                             ^  ^  ^
//              +--------------+  |  +-------------+
//              |                 |                |
//        IsSystemHeapAddress  +--+         MemoryMapLockGuard
//              |              |                   |
//              |          RtlReentrancyLockGuard  |
//              |              |                   |
//              v              v                   v
// +------------+------+ +-----+-------------+ +---+---------------+
// | Win32HeapLock (L) | | Win32HeapLock (L) | | Win32HeapLock (L) |
// | MemoryMapLock ( ) | | MemoryMapLock ( ) | | MemoryMapLock (L) |
// | RtlReentrLock (L) | | RtlReentrLock (L) | | RtlReentrLock (L) |
// +-------------------+ +-------------------+ +-------------------+
// clang-format on

// Note that for the DebugChecks below, we only reason about what locks have
// been taken during the current call and the above graph shows global lock
// status.

struct AsanHeap;

struct DebugChecksData {
  // Holds all the extra debug information needed for the following scenarios:
  //    1. AsanHeapHandle::IsLfhInternal determines whether we're being called
  //       for an internal allocation for the Low Fragmentation Heap by checking
  //       to see if we're a reentrant call to the Rtl function. We need to
  //       check that the RtlReentrancyLock is taken, but also be defensive
  //       about making sure that it isn't taken because we've locked it during
  //       the current call.
  //    2. AllocationOwnership may take the Win32 Heap Lock during the
  //       IsSystemHeapAddress call. Make sure no other AsanHeap locks are held
  //       when this happens.
  //    3. Ensure that the RtlReentrancyLock and Win32 Heap Lock isn't taken
  //       locally when, calling asan functions, or when taking the
  //       MemoryMapLock, but is taken when calling rtl functions.
  //    4. Ensure that the MemoryMapLock is not taken when calling
  //       asan or rtl functions, or when taking the RtlReentrancyLock.
  DebugChecksData() = default;
  DebugChecksData(const DebugChecksData &) = delete;
  DebugChecksData &operator=(const DebugChecksData &) = delete;
  DebugChecksData(DebugChecksData &&) = delete;
  DebugChecksData &operator=(DebugChecksData &&) = delete;

#ifdef SANITIZER_DEBUG
  bool win32_heap_lock_held_locally = false;
  bool rtl_guard_instantiated = false;
  const AsanHeap *asan_heap = nullptr;
#endif
};

struct DebugChecks {
  // AsanHeapHandle and AllocationOwnership derive from this
  // to avoid space overhead in release.
  DebugChecks(DebugChecksData &data)
#ifdef SANITIZER_DEBUG
      : dbg(data)
#endif
  {
  }

#ifdef SANITIZER_DEBUG
  bool Debug_RegisterAsanHeap(AsanHeap *ptr) {
    dbg.asan_heap = ptr;
    return true;
  }

  bool Debug_RegisterReentrancyLockHeld(bool enabled) {
    dbg.rtl_guard_instantiated = enabled;
    return true;
  }

  bool Debug_IsReentrancyLockHeldLocally() const {
    // Note that this returns true even if the RtlReentrancyLock is not required
    // because the Low Fragmentation Heap is not in use.
    return dbg.rtl_guard_instantiated;
  }

  bool Debug_RegisterWin32HeapLockHeld(bool enabled) {
    dbg.win32_heap_lock_held_locally = enabled;
    return true;
  }

  bool Debug_IsWin32HeapLockHeldLocally() const {
    // Note that this returns true even in cases where it is not required
    // because the Low Fragmentation Heap is not in use.
    return dbg.win32_heap_lock_held_locally;
  }

  bool Debug_IsMemoryMapLockHeld();

  bool Debug_AreAnyLocksHeldLocally() {
    return Debug_IsMemoryMapLockHeld() || Debug_IsReentrancyLockHeldLocally() ||
           Debug_IsWin32HeapLockHeldLocally();
  }

  int Debug_GetLockState() {
    int state = 0;
    state += Debug_IsMemoryMapLockHeld() * 0x1;
    state += Debug_IsReentrancyLockHeldLocally() * 0x10;
    state += Debug_IsWin32HeapLockHeldLocally() * 0x100;
    return state;
  }

  static int Debug_CallAsan_TargetLockState() {
    // If calling into other potentially-allocating asan functions,
    // no locks may be taken.
    // See Lock Usage section above for details.
    return 0x000;  // No locks held.
  }

  static int Debug_CallRtl_TargetLockState() {
    // If calling into other potentially-allocating asan functions,
    // the MemoryMapLock must not be taken and RtlReentrancyLock+Win32HeapLock
    // must be taken (if applicable). See Lock Usage section above for details.
    if (LIKELY(!__sanitizer::IsProcessTerminating())) {
      return 0x110;  // Only MemoryMapLock is unlocked.
    }

    // If the process is terminating, the targeted lock state will be unlocked
    // (0x0).
    return 0x000;
  }

#define DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(DBG)           \
  do {                                                        \
    DCHECK_EQ((DBG).Debug_GetLockState(),                     \
              DebugChecks::Debug_CallAsan_TargetLockState()); \
  } while (0)

#define DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(DBG)           \
  do {                                                       \
    DCHECK_EQ((DBG).Debug_GetLockState(),                    \
              DebugChecks::Debug_CallRtl_TargetLockState()); \
  } while (0)

  // Note that we do not need DCHECKs around returns since we are
  // structurally guaranteed to release all locks we've acquired.

  DebugChecksData &dbg;
#else
#define DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(DBG)
#define DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(DBG)
#endif
};

struct AsanHeap {
  struct HEAP {
    // This data structure is undocumented and is subject to change.
    // This is a partial definition and does not represent a full object, only a
    // view on Heap HANDLEs used by Win32 Heap functions.
    void *padding1[2];
    unsigned long signature;

    unsigned long padding2[3];
    void *padding3[10];

    unsigned long flags;
    unsigned long forceFlags;

    HEAP() = delete;
    ~HEAP() = delete;
  };

  static void *operator new(size_t, void *p) { return p; }
  static void *operator new(size_t size) { return InternalAlloc(size); }
  static void operator delete(void *p) { InternalFree(p); }

  explicit AsanHeap(HANDLE _heap) : heap(*((HEAP *)_heap)) {
    constexpr unsigned long HEAP_PROCESS_CLASS = 0x00000000;
    constexpr unsigned long HEAP_PRIVATE_CLASS = 0x00001000;
    constexpr unsigned long HEAP_CLASS_MASK = 0x0000F000;

    constexpr unsigned long HEAP_SUPPORTED_CLASSES[] = {HEAP_PROCESS_CLASS,
                                                        HEAP_PRIVATE_CLASS};

    const unsigned long heapClass =
        (heap.flags | heap.forceFlags) & HEAP_CLASS_MASK;

    bool heapClassSupported = false;
    for (const auto &heapClassType : HEAP_SUPPORTED_CLASSES) {
      if (heapClass == heapClassType) {
        heapClassSupported = true;
        break;
      }
    }

    if (!heapClassSupported) {
      is_supported = false;
      return;
    }

    constexpr unsigned long HEAP_UNSUPPORTED_FLAGS =
        (HEAP_GENERATE_EXCEPTIONS | HEAP_REALLOC_IN_PLACE_ONLY |
         HEAP_CREATE_ENABLE_EXECUTE);

    if ((heap.flags | heap.forceFlags) & HEAP_UNSUPPORTED_FLAGS) {
      is_supported = false;
      return;
    }

    is_supported = true;
  }

  ~AsanHeap() {
    // MemoryMapLockGuard not needed, as this will only occur if there are no
    // more users of the AsanHeap.
    DCHECK(&heap != GetProcessHeap());

    GET_STACK_TRACE_FREE;
    while (!asan_memory.empty()) {
      AsanHeapMemoryNode *node = asan_memory.front();
      asan_free(node->memory, &stack, FROM_MALLOC);
      node->~AsanHeapMemoryNode();
      AsanHeapMemoryNode::operator delete(node, &allocation_cache);
      asan_memory.pop_front();
    }
  }

  void Acquire() { _InterlockedIncrement(&refcount); }

  bool Release() {
    // Returns whether this was destroyed.
    const auto new_refcount = _InterlockedDecrement(&refcount);
    DCHECK(new_refcount >= 0);
    if (new_refcount == 0) {
      delete this;
      return true;
    }
    return false;
  }

  // A reference to some members of the opaque HEAP data structure.
  const HEAP &heap;

  // Lock and thread id to keep the accesses to the map and the list atomic.
  __sanitizer::SpinMutex memory_map_lock = {};
  __sanitizer::atomic_uint32_t memory_map_thread_id = {};

  // Lock and thread id to detect reentrancy for when we need to
  // call the real Rtl functions.
  __sanitizer::SpinMutex rtl_reentrancy_lock = {};
  __sanitizer::atomic_uint32_t rtl_reentrancy_thread_id = {};

  // Instead of guaranteeing exclusive access during delete, maintain a
  // reference count to keep data valid until there are no more users. Use
  // Interlocked ops on refcount.
  long refcount = {1};  // signed, to detect errors

  bool is_supported;

  // A list of memory managed by asan associated with this heap to enable
  // freeing all memory when a heap is destroyed.
  AsanMemoryList asan_memory = {};

  // A mapping of asan managed pointers to the node before them in the list to
  // allow for efficient removal when freed.
  AsanMemoryMap memory_map;

  // To avoid excessive locking of InternalAllocator keep a per-heap
  // allocation_cache.
  InternalAllocatorCache allocation_cache;
};

bool DebugChecks::Debug_IsMemoryMapLockHeld() {
  if (!dbg.asan_heap) {
    return false;
  }

  return atomic_load(&dbg.asan_heap->memory_map_thread_id,
                     __sanitizer::memory_order_seq_cst) == GetCurrentThreadId();
}

struct AsanHeapMap : public __sanitizer::AddrHashMap<AsanHeap *, 37> {
  using __sanitizer::AddrHashMap<AsanHeap *, 37>::Handle;
};

AsanHeapMap *GetAsanHeapMap() { return &immortalize<AsanHeapMap>(); }
AsanHeap *GetDefaultHeap() {
  return &immortalize<AsanHeap, void *>(GetProcessHeap());
}

// The handle takes shared ownership of the AsanHeap.
// AsanHeap is reference counted to ensure it never leaves scope while another
// function is using it. Once it is removed from the AsanHeapMap, deletion
// will wait until all handles are released. Functions that return valid
// memory addresses inside that heap check for destruction prior to
// returning them.
class AsanHeapHandle : public DebugChecks {
 public:
  AsanHeapHandle(const AsanHeapMap::Handle &h, DebugChecks dbg)
      : DebugChecks(dbg), asan_heap_ptr(nullptr) {
    CHECK(h.exists());
    Acquire(*h);
  }

  ~AsanHeapHandle() {
    if (Valid()) {
      Release();
    }
  }

  AsanHeapHandle(const AsanHeapHandle &rhs) : DebugChecks(rhs.dbg) {
    Acquire(rhs.asan_heap_ptr);
  }

  AsanHeapHandle(AsanHeapHandle &&rhs) : DebugChecks(rhs.dbg) {
    Move(&rhs.asan_heap_ptr);
  }

  AsanHeapHandle &operator=(const AsanHeapHandle &rhs) = delete;
  AsanHeapHandle &operator=(AsanHeapHandle &&rhs) = delete;

  bool Valid() const { return asan_heap_ptr; }

  bool IsSupported() const {
    CHECK(Valid());
    return asan_heap_ptr->is_supported;
  }

  [[nodiscard]] unsigned long GetFlags() const {
    CHECK(Valid());
    constexpr unsigned long HEAP_EXAMINED_FLAGS =
        (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY);

    return (asan_heap_ptr->heap.flags | asan_heap_ptr->heap.forceFlags) &
           HEAP_EXAMINED_FLAGS;
  }

  [[nodiscard]] auto MemoryMapLockGuard() & {
    // MemoryMapLock cannot be taken during an asan_malloc/asan_free call,
    // since arbitrary hooks can be applied to malloc/free which may lock
    // themselves. If those hooks do lock, then there will be a lock order
    // inversion, since some asan_malloc calls will occur with the heap handle
    // lock taken, and some will not.
    // The real RTL functions also may take the Win32 Heap Lock, so the
    // MemoryMapLock should not be taken when calling into those either. This
    // function/structure will ensure that the lock is taken while accessing the
    // memory map or memory list, but be sure to have it leave scope as soon as
    // access is no longer needed to avoid any lock order inversion issues.
    CHECK(Valid());
    DCHECK(!Debug_AreAnyLocksHeldLocally());
    DCHECK(!__sanitizer::IsProcessTerminating());

    class MemoryMapLockGuard_impl {
     public:
      explicit MemoryMapLockGuard_impl(AsanHeap &h)
          : raii_lock(h.memory_map_lock, h.memory_map_thread_id),
            asan_memory(h.asan_memory),
            memory_map(h.memory_map),
            allocation_cache(h.allocation_cache) {}

      AsanMemoryList &AsanMemory() & { return asan_memory; }

      AsanMemoryMap &MemoryMap() & { return memory_map; }

      InternalAllocatorCache &Cache() & { return allocation_cache; }

     private:
      RecursiveScopedLock raii_lock;
      AsanMemoryList &asan_memory;
      AsanMemoryMap &memory_map;
      InternalAllocatorCache &allocation_cache;
    } map_guard(*asan_heap_ptr);
    return map_guard;
  }

  [[nodiscard]] auto RtlReentrancyLockGuard() & {
    // When using the Low Fragmentation Heap, there can be a possibility for an
    // Rtl allocation/deallocation function to experience reentrancy into
    // another Rtl function to allocate internals. These internals will not show
    // up when walking the heap and we don't want ASAN handling them, so instead
    // if we detect any reentrancy, we call into the real RTL implementation of
    // the heap functions. Call and take this lock only when LFH is in use.
    // A side effect of this is that while one thread is calling a real Rtl
    // function, another thread cannot call any Rtl function. We also need to
    // take the heap lock while holding this, otherwise we may invert lock
    // ordering. The heap lock must be able to be taken while inside the real
    // RTL function, and may be taken prior as well.
    CHECK(Valid());

    class RtlReentrancyLockGuard_impl {
     public:
      explicit RtlReentrancyLockGuard_impl(AsanHeapHandle &h)
          : heap_handle(h), raii_lock_ptr(nullptr) {
        // Note that debug checks must be done outside LFH check
        // so we maintain our tracking even when not using LFH.
        DCHECK(!heap_handle.Debug_AreAnyLocksHeldLocally());
        DCHECK(heap_handle.Debug_RegisterWin32HeapLockHeld(true));
        DCHECK(heap_handle.Debug_RegisterReentrancyLockHeld(true));
        DCHECK(!__sanitizer::IsProcessTerminating());

        if (heap_handle.IsLowFragmentationHeap()) {
          ::HeapLock(heap_handle.Win32Handle());
          raii_lock_ptr = new (storage) RecursiveScopedLock(
              heap_handle.asan_heap_ptr->rtl_reentrancy_lock,
              heap_handle.asan_heap_ptr->rtl_reentrancy_thread_id);
        }
      }

      ~RtlReentrancyLockGuard_impl() {
        // Note that debug checks must be done even when empty
        // so we maintain our tracking even when not using LFH.
        DCHECK(!heap_handle.Debug_IsMemoryMapLockHeld());

        if (raii_lock_ptr) {
          raii_lock_ptr->~RecursiveScopedLock();
          ::HeapUnlock(heap_handle.Win32Handle());
        }

#if SANITIZER_DEBUG
        if (cleanup_dchecks) {
          DCHECK(heap_handle.Debug_RegisterReentrancyLockHeld(false));
          DCHECK(heap_handle.Debug_RegisterWin32HeapLockHeld(false));
        }
#endif
      }

      RtlReentrancyLockGuard_impl(RtlReentrancyLockGuard_impl &&rhs)
          : heap_handle(rhs.heap_handle), raii_lock_ptr(nullptr) {
        if (rhs.raii_lock_ptr) {
          // This variable indicates whether lock is active, be sure to set to
          // nullptr.
          rhs.raii_lock_ptr = nullptr;
          REAL(memcpy)(&storage, &rhs.storage, sizeof(RecursiveScopedLock));
          raii_lock_ptr = reinterpret_cast<RecursiveScopedLock *>(&storage);
        }
        DCHECK(!(rhs.cleanup_dchecks = false));
      }

      RtlReentrancyLockGuard_impl &&operator=(RtlReentrancyLockGuard_impl &&) =
          delete;
      RtlReentrancyLockGuard_impl(const RtlReentrancyLockGuard_impl &) = delete;
      RtlReentrancyLockGuard_impl &operator=(
          const RtlReentrancyLockGuard_impl &) = delete;

     private:
      AsanHeapHandle &heap_handle;
      alignas(RecursiveScopedLock) unsigned char storage[sizeof(
          RecursiveScopedLock)];
      RecursiveScopedLock *raii_lock_ptr;
#if SANITIZER_DEBUG
      bool cleanup_dchecks = true;
#endif
    } rtl_guard{*this};

    return rtl_guard;
  }

  bool IsLowFragmentationHeap() const {
    CHECK(Valid());
    return asan_heap_ptr->heap.signature == LOW_FRAG_HEAP_SIGNATURE;
  }

  bool IsLfhInternal(const DWORD flags) const {
    CHECK(Valid());

    // Only use this prior to instantiating the RTL reentrancy guard, otherwise
    // may return true.
    DCHECK(!Debug_IsReentrancyLockHeldLocally());

    if (!IsLowFragmentationHeap()) {
      // Only the LFH is reentrant.
      return false;
    }

    if (flags & HEAP_NO_CACHE_BLOCK) {
      // LFH allocations will be marked with this flag when reentrant.
      return true;
    }

    // This check requires that the RtlReentrancyLockGuard is taken during
    // every call back into the real RTL functions.
    DCHECK(!__sanitizer::IsProcessTerminating());
    if (atomic_load(&asan_heap_ptr->rtl_reentrancy_thread_id,
                    __sanitizer::memory_order_seq_cst) ==
        GetCurrentThreadId()) {
      return true;
    }

    return false;
  }

  HANDLE Win32Handle() const {
    CHECK(Valid());
    return (HANDLE)&asan_heap_ptr->heap;
  }

  bool Release() {
    CHECK(Valid());
    DCHECK(!Debug_AreAnyLocksHeldLocally());
    const bool deleted = asan_heap_ptr->Release();
    asan_heap_ptr = nullptr;
    return deleted;
  }

  static AsanHeapHandle GetDefaultHeapHandle(DebugChecks dbg) {
    AsanHeap *default_heap = GetDefaultHeap();
    DCHECK(default_heap);
    return AsanHeapHandle(default_heap, dbg);
  }

 private:
  explicit AsanHeapHandle(AsanHeap *ptr, DebugChecks dbg)
      : DebugChecks(dbg), asan_heap_ptr(nullptr) {
    Acquire(ptr);
  }

  void Acquire(AsanHeap *ptr) {
    asan_heap_ptr = ptr;
    DCHECK(Debug_RegisterAsanHeap(asan_heap_ptr));
    if (asan_heap_ptr) {
      asan_heap_ptr->Acquire();
    }
  }

  void Move(AsanHeap **ptr) {
    asan_heap_ptr = *ptr;
    DCHECK(Debug_RegisterAsanHeap(asan_heap_ptr));
    *ptr = nullptr;
  }

  AsanHeap *asan_heap_ptr;
};

static void DeleteAsanHeap(void *heap_handle) {
  DCHECK(heap_handle != nullptr);
  DCHECK(heap_handle != GetProcessHeap());
  DCHECK(!__sanitizer::IsProcessTerminating());

  AsanHeapMap::Handle h_delete(
      GetAsanHeapMap(), reinterpret_cast<uptr>(heap_handle), true, false);

  if (h_delete.exists()) {
    // Release AsanHeapMap's ownership of asan heap pointer.
    (*h_delete)->Release();
  }
}

static auto GetAsanHeap(void *heap_handle, DebugChecks dbg) {
  DCHECK(heap_handle != nullptr);
  DCHECK(!__sanitizer::IsProcessTerminating());

  if (heap_handle == GetProcessHeap()) {
    return AsanHeapHandle::GetDefaultHeapHandle(dbg);
  }

  AsanHeapMap::Handle h_find_or_create(
      GetAsanHeapMap(), reinterpret_cast<uptr>(heap_handle), false, true);

  if (h_find_or_create.created()) {
    *h_find_or_create = new AsanHeap(heap_handle);  // starts at refcount 1
  }

  // Note that AsanHeapMap::Handle grants shared access, must construct the
  // AsanHeapHandle object while it is in scope to ensure it isn't deleted prior
  // to being acquired.
  return AsanHeapHandle(h_find_or_create, dbg);
}

struct HeapFlags {
  // There are Win32 APIs which may rely on internal undocumented Rtl
  // functions that intend to interop with the Rtl Heap. Since we cannot
  // intercept these APIs, instead we detect which calls are coming from
  // the OS and redirect them back to the real Win32 version via unsupported
  // flags.

  // OS internals also use 'tags' to mark their allocations. We cannot
  // determine individual tags used by different components, since they
  // are dynamically generated, but we can have a blanket policy to
  // not hook the allocation if any tag is detected.

  // For example, (when windows_hook_legacy_allocators=false), memory
  // allocated via GlobalAlloc will be unable to be reallocated via
  // GlobalReAlloc due to because it uses an internal API to verify
  // whether the passed memory is owned by the current heap.

  HeapFlags(DWORD heapFlags, DWORD userFlags, DWORD unsupportedFlags)
      : AllFlags(heapFlags | userFlags) {
    UnsupportedFlags = AllFlags & unsupportedFlags;
    if (flags()->windows_hook_legacy_allocators) {
      // Tagged heaps are not filtered out for performance considerations.
      // If they are filtered out, in a multithreaded application where large
      // quantities of threads are all attempting to read/write from the same
      // heap concurrently, each thread will be contending for both the
      // RtlReentrancyLock and HeapLock.
      //
      // Note that any allocation with a tag in the flags is unsupported if
      // legacy allocators are not being used.
      UnsupportedFlags &= ~HEAP_TAG_MASK;
    }
  }

  DWORD AllFlags;
  DWORD UnsupportedFlags;
};

struct AllocationOwnership : public DebugChecks {
  enum { NEITHER = 0, ASAN = 1, RTL = 2 };
  const int ownership;

  AllocationOwnership(void *heap, void *memory, DebugChecks dbg)
      : DebugChecks(dbg), ownership(get_ownership(memory, heap)) {}

 private:
  int get_ownership(void *memory, void *heap) {
    if (!memory) {
      return NEITHER;
    } else if (__sanitizer_get_ownership(memory)) {
      return ASAN;
    }

    DCHECK(!Debug_AreAnyLocksHeldLocally());
    DCHECK(Debug_RegisterWin32HeapLockHeld(true));
    const bool is_rtl =
        IsSystemHeapAddress(reinterpret_cast<uptr>(memory), heap);
    DCHECK(Debug_RegisterWin32HeapLockHeld(false));
    DCHECK(!Debug_AreAnyLocksHeldLocally());

    if (is_rtl) {
      return RTL;
    }

    return NEITHER;
  }

  friend bool operator==(const AllocationOwnership &l,
                         const AllocationOwnership &r) {
    return l.ownership == r.ownership;
  }

  friend bool operator==(const AllocationOwnership &l, const int &r) {
    return l.ownership == r;
  }

  friend bool operator==(const int &l, const AllocationOwnership &r) {
    return l == r.ownership;
  }

  template <class Other>
  friend bool operator!=(const AllocationOwnership &l, const Other &r) {
    return !(l == r);
  }

  template <class Other>
  friend bool operator!=(const Other &l, const AllocationOwnership &r) {
    return !(l == r);
  }
};

// The following functions are undocumented and subject to change.
// However, hooking them is necessary to hook Windows heap
// allocations with detours and their definitions are unlikely to change.
// Comments in /minkernel/ntos/rtl/heappublic.c indicate that these functions
// are part of the heap's public interface.

// This function is documented as part of the Driver Development Kit but *not*
// the Windows Development Kit.
void *RtlDestroyHeap(void *HeapHandle);

// This function is documented as part of the Driver Development Kit but *not*
// the Windows Development Kit.
LOGICAL RtlFreeHeap(void *HeapHandle, DWORD Flags, void *BaseAddress);

// This function is documented as part of the Driver Development Kit but *not*
// the Windows Development Kit.
void *RtlAllocateHeap(void *HeapHandle, DWORD Flags, size_t Size);

// This function is completely undocumented.
void *RtlReAllocateHeap(void *HeapHandle, DWORD Flags, void *BaseAddress,
                        size_t Size);

// This function is completely undocumented.
size_t RtlSizeHeap(void *HeapHandle, DWORD Flags, void *BaseAddress);

// This function is completely undocmented.
bool RtlValidateHeap(void *HeapHandle, DWORD Flags, void *BaseAddress);

INTERCEPTOR_WINAPI(void *, RtlDestroyHeap, void *HeapHandle) {
  if (UNLIKELY(HeapHandle == nullptr || HeapHandle == GetProcessHeap())) {
    // RtlDestroyHeap won't do anything in these cases, so we don't
    // delete anything either.
    return REAL(RtlDestroyHeap)(HeapHandle);
  }

  // If the process is terminating, we should not grab the write lock of the
  // AsanHeapMap
  if (!__sanitizer::IsProcessTerminating()) {
    DeleteAsanHeap(HeapHandle);
  }

  return REAL(RtlDestroyHeap)(HeapHandle);
}

INTERCEPTOR_WINAPI(size_t, RtlSizeHeap, HANDLE HeapHandle, DWORD Flags,
                   void *BaseAddress) {
  if (UNLIKELY(!asan_inited || !BaseAddress)) {
    // DebugCheck omitted: Asan can't handle the call yet/invalid arguments.
    return REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);
  }

  DebugChecksData dbg_data;
  DebugChecks dbg{dbg_data};

  AllocationOwnership owner(HeapHandle, BaseAddress, dbg);
  if (UNLIKELY(owner != AllocationOwnership::ASAN)) {
    // DebugCheck omitted: RtlSizeHeap does not suffer from a potential
    // reentrancy issue.
    return REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);
  }

  if (!__sanitizer::IsProcessTerminating()) {
    auto heap_handle = GetAsanHeap(HeapHandle, dbg);
    auto access_locked = heap_handle.MemoryMapLockGuard();
    AsanMemoryMap &memory_map = access_locked.MemoryMap();
    // We know that ASAN owns the memory but let's make sure it is owned by
    // this heap.
    AsanMemoryMap::Handle h(&memory_map, reinterpret_cast<uptr>(BaseAddress),
                            false, false);
    // If the pointer is not in the heap's allocated memory map one of
    // two things could be happening:
    // 1. The memory passed into RtlSizeHeap was allocated with malloc or new.
    // 2. ASAN owns the memory but the wrong heap was passed into RtlSizeHeap.
    // We should emit ASan error for this in the future.
    if (!h.exists()) {
      if (HeapHandle != GetProcessHeap()) {
        // TODO: Emit an ASan error because the memory does not belong to the
        // referenced heap. Until then we emulate the behavior of RtlSizeHeap.
        return -1;
      }
    }
  }

  GET_CURRENT_PC_BP_SP;
  (void)sp;
  DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
  return asan_malloc_usable_size(BaseAddress, pc, bp);
}

INTERCEPTOR_WINAPI(bool, RtlValidateHeap, void *HeapHandle, DWORD Flags,
                   void *BaseAddress) {
  if (UNLIKELY(!asan_inited)) {
    // DebugCheck omitted: Asan can't handle the call yet/invalid arguments.
    return REAL(RtlValidateHeap)(HeapHandle, Flags, BaseAddress);
  }

  DebugChecksData dbg_data;
  DebugChecks dbg{dbg_data};

  AllocationOwnership owner(HeapHandle, BaseAddress, dbg);
  if (UNLIKELY(owner != AllocationOwnership::ASAN) || BaseAddress == nullptr) {
    // When BaseAddress is nullptr, the user wants to validate the heap object,
    // not check whether the address is owned by that heap, so pass that on to
    // the real function. DebugCheck omitted: RtlValidateHeap does not suffer
    // from a potential reentrancy issue.
    return REAL(RtlValidateHeap)(HeapHandle, Flags, BaseAddress);
  }

  if (!__sanitizer::IsProcessTerminating()) {
    auto heap_handle = GetAsanHeap(HeapHandle, dbg);
    auto access_locked = heap_handle.MemoryMapLockGuard();
    AsanMemoryMap &memory_map = access_locked.MemoryMap();

    // ASAN owns the memory, but double check heap handle is correct.
    AsanMemoryMap::Handle h(&memory_map, reinterpret_cast<uptr>(BaseAddress),
                            false, false);
    if (!h.exists()) {
      return false;
    }
  }

  // Already confirmed __sanitizer_get_ownership(BaseAddress) == true in
  // AllocationOwnership.
  return true;
}

INTERCEPTOR_WINAPI(void *, RtlAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   size_t Size) {
  if (UNLIKELY(!asan_inited || __sanitizer::IsProcessTerminating())) {
    // DebugCheck omitted: Asan can't handle the call yet.
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  DebugChecksData dbg_data;
  DebugChecks dbg{dbg_data};

  auto heap_handle = GetAsanHeap(HeapHandle, dbg);
  auto [all_flags, asan_unsupported_flags] =
      HeapFlags(heap_handle.GetFlags(), Flags, HEAP_ALLOCATE_UNSUPPORTED_FLAGS);

  // NOTE:
  //
  // ASAN won't place this allocation inside of a heap from RtlCreateHeap like
  // REAL(RtlAllocateHeap) would. When ASAN intercepts RtlAllocateHeap, the
  // allocation instead will live inside the ASAN allocator. The HeapHandle
  // parameter is used for tracking which heap the allocation is meant to belong
  // to, but the allocation doesn't actually live there. This is problematic for
  // applications that make use of mapped memory, specifically in the case of
  // multiple actors passing around relative addresses and expecting allocations
  // to be at a particular location. If memory is mapped, we delegate back to
  // the real Rtl* functions.

  if (UNLIKELY(!heap_handle.IsSupported() || asan_unsupported_flags ||
               heap_handle.IsLfhInternal(Flags) || IsMemoryMapped(HeapHandle))) {
    auto rtlguard = heap_handle.RtlReentrancyLockGuard();

    DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  GET_STACK_TRACE_MALLOC;

  DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
  void *p = asan_malloc(Size, &stack);

  // Reading MSDN suggests that the *entire* usable allocation is zeroed out.
  // Otherwise it is difficult to HeapReAlloc with HEAP_ZERO_MEMORY.
  // https://blogs.msdn.microsoft.com/oldnewthing/20120316-00/?p=8083
  //
  // NOTE:
  //
  // There is no guarantee nor good indicator of predicting whether memory
  // will be zeroed out unless using the HEAP_ZERO_MEMORY flag. The
  // noninstrumented calls to RtlAllocateHeap may return zeroed out memory, but
  // those cases are from large allocations that go directly to VirtualAlloc for
  // its memory, which is guaranteed by the OS to be zeroed. The
  // malloc_fill_byte option=00 can be used by the user to instruct the asan
  // allocator to fill allocated memory with zeros up to max_malloc_fill_size
  // option.
  if (p && (all_flags & HEAP_ZERO_MEMORY)) {
    GET_CURRENT_PC_BP_SP;
    (void)sp;
    DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
    auto usable_size = asan_malloc_usable_size(p, pc, bp);
    internal_memset(p, 0, usable_size);
  }

  {
    auto access_locked = heap_handle.MemoryMapLockGuard();
    AsanMemoryList &asan_memory = access_locked.AsanMemory();
    AsanMemoryMap &memory_map = access_locked.MemoryMap();

    AsanHeapMemoryNode *mem_node =
        new (&access_locked.Cache()) AsanHeapMemoryNode(p);
    AsanHeapMemoryNode *prev_tail = asan_memory.back();
    asan_memory.push_back(mem_node);

    {
      AsanMemoryMap::Handle h(&memory_map, reinterpret_cast<uptr>(p), false,
                              true);
      *h = prev_tail;
    }
  }

  return p;
}

static void __asan_wrap_RtlFreeHeap_UpdateTracking(AsanHeapHandle &heap_handle,
                                                   void *BaseAddress) {
  auto access_locked = heap_handle.MemoryMapLockGuard();
  AsanMemoryList &asan_memory = access_locked.AsanMemory();
  AsanMemoryMap &memory_map = access_locked.MemoryMap();

  AsanHeapMemoryNode *found;
  {
    AsanMemoryMap::Handle h_delete(
        &memory_map, reinterpret_cast<uptr>(BaseAddress), true, false);

    // If the pointer is not in the heap's allocated memory map one of
    // two things could be happening:
    // 1. The memory passed into RtlFreeHeap was allocated with malloc or new.
    // 2. ASAN owns the memory but the wrong heap was passed into RtlFreeHeap.
    // We should emit ASan error for this in the future.
    if (!h_delete.exists()) {
      if (heap_handle.Win32Handle() != GetProcessHeap()) {
        // TODO: Emit an ASan error because the memory does not belong to the
        // referenced heap.
      }

      return;
    }
    found = *h_delete;
  }

  AsanHeapMemoryNode *remove;
  AsanHeapMemoryNode *update;
  if (found) {
    remove = found->next;
    asan_memory.extract(found, found->next);
    update = found->next;
  } else {
    remove = asan_memory.front();
    asan_memory.pop_front();
    update = asan_memory.front();
  }

  CHECK(remove->memory == BaseAddress &&
        "Memory list is inconsistent with map. "
        "This is a bug, please report it.");

  if (update) {
    {
      AsanMemoryMap::Handle h_update(
          &memory_map, reinterpret_cast<uptr>(update->memory), true, false);
    }
    {
      AsanMemoryMap::Handle h_update(
          &memory_map, reinterpret_cast<uptr>(update->memory), false, true);
      *h_update = found;
    }
  }

  remove->~AsanHeapMemoryNode();
  AsanHeapMemoryNode::operator delete(remove, &access_locked.Cache());
}

INTERCEPTOR_WINAPI(LOGICAL, RtlFreeHeap, void *HeapHandle, DWORD Flags,
                   void *BaseAddress) {
  if (UNLIKELY(!asan_inited || !BaseAddress || IsMemoryMapped(HeapHandle))) {
    // DebugCheck omitted: Asan can't handle the call yet/invalid arguments.
    return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
  }

  DebugChecksData dbg_data;
  DebugChecks dbg{dbg_data};

  AllocationOwnership owner(HeapHandle, BaseAddress, dbg);

  if (LIKELY(!__sanitizer::IsProcessTerminating())) {
    auto heap_handle = GetAsanHeap(HeapHandle, dbg);

    if (UNLIKELY(owner == AllocationOwnership::RTL || IsMemoryMapped(HeapHandle))) {
      auto rtlguard = heap_handle.RtlReentrancyLockGuard();

      DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
      return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
    }

    if (owner == AllocationOwnership::NEITHER) {
      if (UNLIKELY(heap_handle.IsLfhInternal(Flags))) {
        auto rtlguard = heap_handle.RtlReentrancyLockGuard();

        DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
        return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
      }

      GET_STACK_TRACE_FREE;
      // This should either return double-free or wild pointer errors
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
      asan_free(BaseAddress, &stack, FROM_MALLOC);

      return false;
    }

    __asan_wrap_RtlFreeHeap_UpdateTracking(heap_handle, BaseAddress);
  } else {
    // If the process is terminating, we do not want to obtain any locks.
    // Instead, we will just call the free for whichever allocation owner is
    // present without attempting to lock.
    if (owner == AllocationOwnership::RTL ||
        owner == AllocationOwnership::NEITHER) {
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
      return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
    }
  }

  GET_STACK_TRACE_FREE;
  DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
  asan_free(BaseAddress, &stack, FROM_MALLOC);

  return true;
}

INTERCEPTOR_WINAPI(void *, RtlReAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   void *BaseAddress, size_t Size) {
  if (UNLIKELY(!asan_inited || __sanitizer::IsProcessTerminating())) {
    // DebugCheck omitted: Asan can't handle the call yet/invalid arguments.
    return REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);
  }

  if (UNLIKELY(!BaseAddress)) {
    // DebugCheck omitted: Calling back directly into our implementation.
    return WRAP(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  DebugChecksData dbg_data;
  DebugChecks dbg{dbg_data};

  AllocationOwnership owner(HeapHandle, BaseAddress, dbg);
  auto heap_handle = GetAsanHeap(HeapHandle, dbg);

  if (UNLIKELY(!heap_handle.IsSupported() || heap_handle.IsLfhInternal(Flags) ||
                 IsMemoryMapped(HeapHandle))) {
    auto rtlguard = heap_handle.RtlReentrancyLockGuard();

    DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
    return REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);
  }

  auto [all_flags, asan_unsupported_flags] =
      HeapFlags(heap_handle.GetFlags(), Flags, HEAP_REALLOC_UNSUPPORTED_FLAGS);

  GET_STACK_TRACE_MALLOC;
  GET_CURRENT_PC_BP_SP;
  (void)sp;

  void *replacement_alloc = nullptr;
  size_t old_size;

  if (owner == AllocationOwnership::NEITHER) {
    // This should cause a use-after-free or wild pointer error. If it is a
    // wild pointer error the pointer was either nonsense or came from
    // another heap.

    DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
    replacement_alloc = asan_realloc(BaseAddress, Size, &stack);

    CHECK((all_flags & HEAP_ZERO_MEMORY) == 0 &&
          "We cannot zero the memory as we do not know the previous size of "
          "the memory. This error should only occur if ASAN errors are "
          "non-fatal.");

    if (replacement_alloc) {
      auto access_locked = heap_handle.MemoryMapLockGuard();
      AsanMemoryList &asan_memory = access_locked.AsanMemory();
      AsanMemoryMap &memory_map = access_locked.MemoryMap();

      AsanHeapMemoryNode *mem_node =
          new (&access_locked.Cache()) AsanHeapMemoryNode(replacement_alloc);
      AsanHeapMemoryNode *prev_tail = asan_memory.back();
      asan_memory.push_back(mem_node);

      AsanMemoryMap::Handle h(
          &memory_map, reinterpret_cast<uptr>(replacement_alloc), false, true);
      *h = prev_tail;
    }
  } else if (!asan_unsupported_flags && owner == AllocationOwnership::ASAN) {
    // HeapReAlloc and HeapAlloc both happily accept 0 sized allocations.
    // passing a 0 size into asan_realloc will free the allocation.
    // To avoid this and keep behavior consistent, fudge the size if 0.
    // (asan_malloc already does this)
    if (Size == 0) {
      Size = 1;
    }

    if (all_flags & HEAP_ZERO_MEMORY) {
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
      old_size = asan_malloc_usable_size(BaseAddress, pc, bp);
    }

    DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
    replacement_alloc = asan_realloc(BaseAddress, Size, &stack);
    if (replacement_alloc == nullptr) {
      return nullptr;
    }

    if (all_flags & HEAP_ZERO_MEMORY) {
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
      size_t new_size = asan_malloc_usable_size(replacement_alloc, pc, bp);
      if (old_size < new_size) {
        // DebugCheck omitted: Memset does not allocate.
        REAL(memset)
        (((u8 *)replacement_alloc) + old_size, 0, new_size - old_size);
      }
    }

    // We need to remove the old pointer from both the heap list and the heap
    // map and then add the new pointer.
    if (replacement_alloc != BaseAddress) {
      auto access_locked = heap_handle.MemoryMapLockGuard();
      AsanMemoryList &asan_memory = access_locked.AsanMemory();
      AsanMemoryMap &memory_map = access_locked.MemoryMap();

      AsanHeapMemoryNode *found;
      bool new_malloc_rtl_mismatch = false;
      {
        AsanMemoryMap::Handle h_delete(
            &memory_map, reinterpret_cast<uptr>(BaseAddress), true, false);

        // If the pointer is not in the heap's allocated memory map one of
        // two things could be happening:
        // 1. The memory passed into RtlReAllocateHeap was allocated with malloc
        // or new. We should emit an error for this.
        // 2. ASAN owns the memory but the wrong heap was passed into
        // RtlReAllocateHeap. We should emit an ASan error in the future.
        if (!h_delete.exists()) {
          if (HeapHandle == GetProcessHeap()) {
            new_malloc_rtl_mismatch = true;
          } else {
            // TODO: Emit an ASan error here
            new_malloc_rtl_mismatch = true;
          }
        }

        found = *h_delete;
      }

      if (!new_malloc_rtl_mismatch) {
        if (found) {
          found->next->memory = replacement_alloc;
        } else {
          asan_memory.front()->memory = replacement_alloc;
        }
      } else {
        // If the function which created this allocation was not an Rtl
        // function we just add the new memory onto the end of the linked
        // list.
        // TODO: Emit an ASan error here
        AsanHeapMemoryNode *mem_node =
            new (&access_locked.Cache()) AsanHeapMemoryNode(replacement_alloc);
        found = asan_memory.back();
        asan_memory.push_back(mem_node);
      }

      AsanMemoryMap::Handle h_new(
          &memory_map, reinterpret_cast<uptr>(replacement_alloc), false, true);
      *h_new = found;
    }
  } else if (UNLIKELY(!asan_unsupported_flags &&
                      owner == AllocationOwnership::RTL)) {
    // DebugCheck omitted: RtlSizeHeap is not re-entrant.
    old_size = REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);

    if (old_size != ~size_t{0}) {
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
      replacement_alloc = WRAP(RtlAllocateHeap)(HeapHandle, Flags, Size);

      if (replacement_alloc == nullptr) {
        return nullptr;
      } else {
        // DebugCheck omitted: memcpy does not allocate.
        REAL(memcpy)
        (replacement_alloc, BaseAddress, Min<size_t>(Size, old_size));

        auto rtlguard = heap_handle.RtlReentrancyLockGuard();

        DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
        REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
      }
    } else {
      return nullptr;
    }
  } else if (UNLIKELY(asan_unsupported_flags &&
                      owner == AllocationOwnership::ASAN)) {
    // For cases with HEAP_REALLOC_IN_PLACE_ONLY, we need to maintain
    // parity with RtlReAllocateHeap and not move the allocation
    // if the size is larger than the previously allocated size. If it
    // is larger, fail (i.e. return nullptr). Otherwise, return the same
    // base address.
    //
    // TODO: BUG #1802790
    // This isn't exactly correct behavior. If ASAN owns the heap, and a user calls
    // RtlReAllocateHeap with a size smaller than what is currently allocated, ASAN
    // should be shrinking the heap in place and adjusting poisoning. This
    // requires changes to SizeClassAllocator to not move memory while shrinking.
    if (all_flags & HEAP_REALLOC_IN_PLACE_ONLY) {
      DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
      old_size = asan_malloc_usable_size(BaseAddress, pc, bp);
      if(old_size < Size)
      {
        return nullptr;
      }
      else
      {
        replacement_alloc = BaseAddress;
      }
    }
    else
    {
      // Conversion to unsupported flags allocation,
      // transfer this allocation to the original allocator.
      {
        auto rtlguard = heap_handle.RtlReentrancyLockGuard();

        DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
        replacement_alloc = REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
      }

      if (replacement_alloc) {
        DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
        old_size = asan_malloc_usable_size(BaseAddress, pc, bp);

        // DebugChecks omitted: memcpy does not allocate.
        REAL(memcpy)(replacement_alloc, BaseAddress, Min<size_t>(Size, old_size));

        DCHECK_ASSERT_LOCK_INVARIANT_CALL_ASAN(dbg);
        WRAP(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
      }
    }
  } else if (UNLIKELY(asan_unsupported_flags &&
                      owner == AllocationOwnership::RTL)) {
    // Currently owned by rtl using unsupported ASAN flags,
    // just pass back to original allocator.
    auto rtlguard = heap_handle.RtlReentrancyLockGuard();

    DCHECK_ASSERT_LOCK_INVARIANT_CALL_RTL(dbg);
    replacement_alloc =
        REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);
  }

  return replacement_alloc;
}

namespace __asan {
// Global and Local have some distinct (but deprecated and ignored) flags,
// we'll seperate them to validate these appropriately.
constexpr unsigned long SHARED_ALLOC_SUPPORTED_FLAGS =
    (FIXED | ZEROINIT | MOVEABLE | MODIFY | NOCOMPACT);

constexpr unsigned long SHARED_ALLOC_UNSUPPORTED_FLAGS =
    (~SHARED_ALLOC_SUPPORTED_FLAGS);

constexpr unsigned long GLOBAL_ALLOC_SUPPORTED_FLAGS =
    (GLOBAL_DISCARDABLE | GLOBAL_NOT_BANKED | GLOBAL_NOTIFY | GLOBAL_SHARE);
constexpr unsigned long LOCAL_ALLOC_SUPPORTED_FLAGS = (LOCAL_DISCARDABLE);
constexpr unsigned long LOCAL_ALLOC_UNSUPPORTED_FLAGS =
    ~(SHARED_ALLOC_SUPPORTED_FLAGS | LOCAL_ALLOC_SUPPORTED_FLAGS);
constexpr unsigned long GLOBAL_ALLOC_UNSUPPORTED_FLAGS =
    ~(SHARED_ALLOC_SUPPORTED_FLAGS | GLOBAL_ALLOC_SUPPORTED_FLAGS);

constexpr unsigned long COMBINED_GLOBALLOCAL_SUPPORTED_FLAGS =
    (SHARED_ALLOC_SUPPORTED_FLAGS | LOCAL_ALLOC_SUPPORTED_FLAGS |
     GLOBAL_ALLOC_SUPPORTED_FLAGS);

constexpr unsigned long COMBINED_GLOBALLOCAL_UNSUPPORTED_FLAGS =
    ~(SHARED_ALLOC_SUPPORTED_FLAGS | LOCAL_ALLOC_SUPPORTED_FLAGS |
      GLOBAL_ALLOC_SUPPORTED_FLAGS);

// forward declaring a few items for the shared versions of some of these
// Global/Local interceptors.
using GlobalLocalAlloc = HANDLE(WINAPI *)(UINT, SIZE_T);
using GlobalLocalRealloc = HANDLE(WINAPI *)(HANDLE, SIZE_T, UINT);
using GlobalLocalSize = SIZE_T(WINAPI *)(HANDLE);
using GlobalLocalFree = HANDLE(WINAPI *)(HANDLE);
using GlobalLocalFlags = UINT(WINAPI *)(HANDLE);
template<__asan_win_moveable::HeapCaller Caller>
HANDLE GlobalLocalGenericFree(HANDLE hMem, BufferedStackTrace &stack);

enum class AllocationOwnershipStatus {
  OWNED_BY_UNKNOWN,
  OWNED_BY_ASAN,
  OWNED_BY_RTL,
  OWNED_BY_GLOBAL_OR_LOCAL,
  OWNED_BY_GLOBAL_OR_LOCAL_HANDLE,
};

AllocationOwnershipStatus CheckGlobalLocalHeapOwnership(
    HANDLE hMem, GlobalLocalLock lockFunc, GlobalLocalUnlock unlockFunc) {
  /*  To figure the validity of hMem, we use GlobalLock/LocalLock. Those two
   * functions can return three things: (1) the pointer that's passed in, in
   * which case it is a pointer owned by the Global/Local heap (2) the pointer
   * to the allocated object if it's a Global/Local heap HANDLE (3) nullptr if
   * it's a pointer which does not belong to the Global/Local heap Using these
   * three return types, we figure out if the pointer is TYPE_VALID_PTR or
   * TYPE_HANDLE or TYPE_UNKNOWN_PTR
   *
   * NOTE: As an implementation detail, moveable memory objects also live on the
   * heap. IsSystemHeapAddress will return true if given a moveable memory
   * handle.
   *
   */

  // Check whether this pointer belongs to the memory manager first.
  if (__asan_win_moveable::IsOwned(hMem) || hMem == nullptr) {
    return AllocationOwnershipStatus::OWNED_BY_ASAN;
  }

  // If the address passed in to check is a handle to a moveable allocation
  // rather than the first byte of the allocation, we need to verify that
  // it doesn't belong to the process heap as well, but only as a last resort.
  static auto IsHandleOnProcessHeap = [](uptr hMem) {
    if (auto potentialHandle = reinterpret_cast<uptr *>(hMem);
        potentialHandle && *potentialHandle) {
      return IsSystemHeapAddress(*potentialHandle, GetProcessHeap());
    }
    return false;
  };

  // It is not safe to pass wild pointers to GlobalLock/LocalLock.
  if (IsSystemHeapAddress(reinterpret_cast<uptr>(hMem), GetProcessHeap()) ||
      IsSystemHeapHandle(reinterpret_cast<uptr>(hMem), GetProcessHeap()) ||
      IsHandleOnProcessHeap(reinterpret_cast<uptr>(hMem))) {
    // TODO:
    // At this point, we know that the allocation exists on the process heap.
    // However, we don't know how to classify the allocation. It could be from
    // malloc, GlobalAlloc, LocalAlloc, etc. If something is malloced before
    // ASAN init, then we attempt to GlobalLock after ASAN init, we will not
    // create an error report for invalid handle at this time. We won't have a
    // wild pointer after the checks above, but if RtlIsValidHandle fails, we
    // can wind up with a debug break below.
    void *ptr = lockFunc(hMem);
    // We don't care whether ptr is moved after this point as we're just trying
    // to determine where it came from.
    unlockFunc(hMem);
    if (ptr == hMem) {
      return AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL;
    } else if (ptr != nullptr) {
      return AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE;
    }
  }
  return AllocationOwnershipStatus::OWNED_BY_UNKNOWN;
}

template<__asan_win_moveable::HeapCaller Caller>
bool NotOwnedByASAN(HANDLE hMem);

template <__asan_win_moveable::HeapCaller Caller>
void *ReAllocGlobalLocal(HANDLE hMem,
                         SIZE_T dwBytes, UINT uFlags,
                         BufferedStackTrace &stack);

}  // namespace __asan

template<__asan_win_moveable::HeapCaller Caller>
HANDLE SharedLock(HANDLE hMem, BufferedStackTrace &stack);

template<__asan_win_moveable::HeapCaller Caller>
BOOL SharedUnlock(HANDLE hMem, BufferedStackTrace &stack);



INTERCEPTOR_WINAPI(HGLOBAL, GlobalAlloc, UINT uFlags, SIZE_T dwBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & GLOBAL_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(GlobalAlloc)(uFlags, dwBytes);
  }
  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::Alloc(uFlags, dwBytes, stack);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalLock, HGLOBAL hMem) {
  GET_STACK_TRACE_MALLOC;
  return SharedLock<__asan_win_moveable::HeapCaller::GLOBAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(int, GlobalUnlock, HGLOBAL hMem) {
  GET_STACK_TRACE_MALLOC;
  return SharedUnlock<__asan_win_moveable::HeapCaller::GLOBAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalFree, HGLOBAL hMem) {
  GET_STACK_TRACE_FREE;
  return GlobalLocalGenericFree<__asan_win_moveable::HeapCaller::GLOBAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalHandle, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, or if reallocation logic defers to REAL(*) functions.
  // If it is not owned by RTL heap, then we can pass it to
  // ASAN heap for inspection.
  //
  // If ASAN is not initialized then this needs to be default passed to the
  // original allocator. If the allocation is owned by the RTL then just
  // keep it there, since it's a leftover from before asan_init was called.
  if(NotOwnedByASAN<__asan_win_moveable::HeapCaller::GLOBAL>(hMem)) {
        return REAL(GlobalHandle)(hMem);
  }
  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::ResolvePointerToHandle(hMem, stack);
}

INTERCEPTOR_WINAPI(UINT, GlobalFlags, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, so if it is not owned by RTL heap, then we can
  // pass it to ASAN heap for inspection.
  //
  // If ASAN is not initialized then this needs to be default passed to the
  // original allocator. If the allocation is owned by the RTL then just
  // keep it there, since it's a leftover from before asan_init was called.
  if(NotOwnedByASAN<__asan_win_moveable::HeapCaller::GLOBAL>(hMem)) {
        return REAL(GlobalFlags)(hMem);
  }
  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::Flags(hMem, stack);
}

INTERCEPTOR_WINAPI(SIZE_T, GlobalSize, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, so if it is not owned by RTL heap, then we can
  // pass it to ASAN heap for inspection.
  if(NotOwnedByASAN<__asan_win_moveable::HeapCaller::GLOBAL>(hMem)) {
    return REAL(GlobalSize)(hMem);
  }

  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::GetAllocationSize(hMem, stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalLock, HLOCAL hMem) {
  GET_STACK_TRACE_MALLOC;
  return SharedLock<__asan_win_moveable::HeapCaller::LOCAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(BOOL, LocalUnlock, HLOCAL hMem) {
  GET_STACK_TRACE_MALLOC;
  return SharedUnlock<__asan_win_moveable::HeapCaller::LOCAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalHandle, HLOCAL hMem) {
  if (NotOwnedByASAN<__asan_win_moveable::HeapCaller::LOCAL>(hMem)) {
    return REAL(LocalHandle)(hMem);
  }
  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::ResolvePointerToHandle(hMem, stack);
}

INTERCEPTOR_WINAPI(UINT, LocalFlags, HLOCAL hMem) {
  if (NotOwnedByASAN<__asan_win_moveable::HeapCaller::LOCAL>(hMem)) {
    return REAL(LocalFlags)(hMem);
  }
  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::Flags(hMem, stack);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalReAlloc, HGLOBAL hMem, SIZE_T dwBytes,
                   UINT uFlags) {
  GET_STACK_TRACE_MALLOC;
  return ReAllocGlobalLocal<__asan_win_moveable::HeapCaller::GLOBAL>((HANDLE)hMem, dwBytes, uFlags, stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalAlloc, UINT uFlags, SIZE_T uBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & LOCAL_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(LocalAlloc)(uFlags, uBytes);
  }

  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::Alloc(uFlags, uBytes, stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalFree, HGLOBAL hMem) {
  // If the memory we are trying to free is not owned
  // ASan heap, then fall back to the original LocalFree.
  GET_STACK_TRACE_FREE;
  return GlobalLocalGenericFree<__asan_win_moveable::HeapCaller::LOCAL>(hMem, stack);
}

INTERCEPTOR_WINAPI(SIZE_T, LocalSize, HGLOBAL hMem) {
  /* We need to check whether the ASAN allocator owns the pointer we're about to
   * use. Allocations might occur before interception takes place, so if it is
   * not owned by RTL heap, the we can pass it to ASAN heap for inspection.*/
  if (NotOwnedByASAN<__asan_win_moveable::HeapCaller::LOCAL>(hMem)) {
    return REAL(LocalSize)(hMem);
  }

  GET_STACK_TRACE_MALLOC;
  return __asan_win_moveable::GetAllocationSize(hMem, stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalReAlloc, HGLOBAL hMem, SIZE_T dwBytes,
                   UINT uFlags) {
  GET_STACK_TRACE_MALLOC;
  return ReAllocGlobalLocal<__asan_win_moveable::HeapCaller::LOCAL>((HANDLE)hMem, dwBytes, uFlags,stack);
}

// Constructs the group of necessary function pointers to be used in Global/Local
// interceptors. 
template <__asan_win_moveable::HeapCaller Caller>
struct GlobalLocalFunctions {
  GlobalLocalFunctions() {
    if constexpr (Caller == __asan_win_moveable::HeapCaller::GLOBAL) {
      LockFunc = REAL(GlobalLock);
      UnlockFunc = REAL(GlobalUnlock);
      AllocFunc = REAL(GlobalAlloc);
      ReallocFunc = REAL(GlobalReAlloc);
      FlagsFunc = REAL(GlobalFlags);
      FreeFunc = REAL(GlobalFree);
      SizeFunc = REAL(GlobalSize);
    } else {
      LockFunc = REAL(LocalLock);
      UnlockFunc = REAL(LocalUnlock);
      AllocFunc = REAL(LocalAlloc);
      ReallocFunc = REAL(LocalReAlloc);
      FlagsFunc = REAL(LocalFlags);
      FreeFunc = REAL(LocalFree);
      SizeFunc = REAL(LocalSize);
    }
    DCHECK(AllocFunc != nullptr);
    DCHECK(ReallocFunc != nullptr);
    DCHECK(FlagsFunc != nullptr);
    DCHECK(FreeFunc != nullptr);
    DCHECK(LockFunc != nullptr);
    DCHECK(UnlockFunc != nullptr);
    DCHECK(SizeFunc != nullptr);
  }

  GlobalLocalLock LockFunc = nullptr;
  GlobalLocalUnlock UnlockFunc = nullptr;
  GlobalLocalAlloc AllocFunc = nullptr;
  GlobalLocalRealloc ReallocFunc = nullptr;
  GlobalLocalFlags FlagsFunc = nullptr;
  GlobalLocalFree FreeFunc = nullptr;
  GlobalLocalSize SizeFunc = nullptr;
};

template<__asan_win_moveable::HeapCaller Caller>
HANDLE SharedLock(HANDLE hMem, BufferedStackTrace &stack)
{
  auto lock = GlobalLocalFunctions<Caller>{}.LockFunc;
  if (asan_inited && !__sanitizer::IsProcessTerminating() &&
      !NotOwnedByASAN<Caller>(hMem)) {
    return __asan_win_moveable::IncrementLockCount(hMem, lock, stack);
  }
  // The memory belongs to an RtlHeap or asan is not yet initialized:
  return lock(hMem);
}

template<__asan_win_moveable::HeapCaller Caller>
BOOL SharedUnlock(HANDLE hMem, BufferedStackTrace &stack)
{
  auto unlock = GlobalLocalFunctions<Caller>{}.UnlockFunc;
  if (asan_inited && !__sanitizer::IsProcessTerminating() &&
      !NotOwnedByASAN<Caller>(hMem)) {
    return __asan_win_moveable::DecrementLockCount(hMem, unlock, stack);
  }
  // The memory belongs to an RtlHeap or asan is not yet initialized:
  return unlock(hMem);
}

namespace __asan {

template<__asan_win_moveable::HeapCaller Caller>
bool NotOwnedByASAN(HANDLE hMem) {
  GlobalLocalFunctions<Caller> functions;
  auto ownershipState =
      CheckGlobalLocalHeapOwnership(hMem, functions.LockFunc, functions.UnlockFunc);

  // If ASAN is not initialized then this needs to be default passed to the
  // original allocator. If the allocation is owned by the RTL then just
  // keep it there, since it's a leftover from before asan_init was called.
  if (UNLIKELY(!asan_inited) ||
      ((ownershipState ==
        AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE) ||
       (ownershipState ==
        AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL))) {
    return true;
  }

  return false;
}

template <__asan_win_moveable::HeapCaller Caller>
HANDLE GlobalLocalGenericFree(HANDLE hMem,
                              BufferedStackTrace &stack) {
  // If the memory we are trying to free is not owned
  // by ASan heap, then fall back to the original GlobalFree.

  // Although the stack trace won't be quite as pretty, by doing this we can
  // avoid tracking which fixed allocations were already freed since RtlFreeHeap
  // will handle double-free detection.
  auto globalLocalFunctions = GlobalLocalFunctions<Caller>{};
  if (__asan_win_moveable::IsOwned(hMem) || hMem == nullptr) {
    return __asan_win_moveable::Free(hMem, stack);
  }

  // Only call free if not null, but we need to lock to check.
  HGLOBAL pointer = globalLocalFunctions.LockFunc(hMem);

  if (pointer == nullptr) {
    // Report invalid pointer.
    return __asan_win_moveable::Free(hMem, stack);
  }

  if (pointer != hMem) {
    // Only unlock moveable pointers.
    globalLocalFunctions.UnlockFunc(hMem);
  }

  return globalLocalFunctions.FreeFunc(hMem);
}

template <__asan_win_moveable::HeapCaller Caller>
void *ReAllocGlobalLocal(HANDLE hMem,
                         SIZE_T dwBytes, UINT uFlags,
                         BufferedStackTrace &stack) {
  auto globalLocalFunctions = GlobalLocalFunctions<Caller>{};

  auto ownershipState =
      CheckGlobalLocalHeapOwnership(hMem, globalLocalFunctions.LockFunc, globalLocalFunctions.UnlockFunc);

  // If ASAN is not initialized then this needs to be default passed to the
  // original allocator. If the allocation is owned by the RTL then just
  // keep it there, since it's a leftover from before asan_init was called.
  if (UNLIKELY(!asan_inited) ||
      ((ownershipState ==
        AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE) ||
       (ownershipState == AllocationOwnershipStatus::OWNED_BY_GLOBAL_OR_LOCAL))) {
    return globalLocalFunctions.ReallocFunc(hMem, dwBytes, uFlags);
  }
  // If the pointer is nonsense pass it directly to asan to report on it.
  if (ownershipState == AllocationOwnershipStatus::OWNED_BY_UNKNOWN) {
    return asan_realloc(hMem, dwBytes, &stack);
  }

  if (ownershipState == AllocationOwnershipStatus::OWNED_BY_ASAN) {
    CHECK((COMBINED_GLOBALLOCAL_UNSUPPORTED_FLAGS & uFlags) == 0);
    return __asan_win_moveable::ReAllocate(hMem, uFlags, dwBytes, Caller,
                                           stack);
  }
  return nullptr;
}
template void *ReAllocGlobalLocal<__asan_win_moveable::HeapCaller::GLOBAL>(HANDLE hMem,
                         SIZE_T dwBytes, UINT uFlags,
                         BufferedStackTrace &stack);
template void *ReAllocGlobalLocal<__asan_win_moveable::HeapCaller::LOCAL>(HANDLE hMem,
                         SIZE_T dwBytes, UINT uFlags,
                         BufferedStackTrace &stack);



}  // namespace __asan

namespace __asan {

static void TryToOverrideFunction(const char *fname, uptr new_func) {
  // Failure here is not fatal. The CRT may not be present, and different CRT
  // versions use different symbols.
  if (!__interception::OverrideFunction(fname, new_func))
    VPrintf(2, "Failed to override function %s\n", fname);
}

void ReplaceSystemMalloc() {
  TryToOverrideFunction("_aligned_malloc", (uptr)_aligned_malloc);
  TryToOverrideFunction("_aligned_offset_malloc", (uptr)_aligned_offset_malloc);
  TryToOverrideFunction("_calloc_base", (uptr)calloc);
  TryToOverrideFunction("_calloc_crt", (uptr)calloc);
  TryToOverrideFunction("_malloc_base", (uptr)malloc);
  TryToOverrideFunction("_malloc_crt", (uptr)malloc);
  TryToOverrideFunction("calloc", (uptr)calloc);
  TryToOverrideFunction("malloc", (uptr)malloc);
  TryToOverrideFunction("_aligned_malloc_dbg", (uptr)_aligned_malloc_dbg);
  TryToOverrideFunction("_aligned_offset_malloc_dbg",
                        (uptr)_aligned_offset_malloc_dbg);
  TryToOverrideFunction("_calloc_dbg", (uptr)_calloc_dbg);
  TryToOverrideFunction("_malloc_dbg", (uptr)_malloc_dbg);

  // We should intercept these functions but it's okay that we don't right now.
  // All of these functions are currently implemented as no-ops for ASan and
  // allowing an instrumented DLL to forward to the actual CRT functions
  // shouldn't significantly affect ASan diagnostics.
  // TryToOverrideFunction("_CrtCheckMemory", (uptr)_CrtCheckMemory);
  // TryToOverrideFunction("_CrtDoForAllClientObjects",
  //                      (uptr)_CrtDoForAllClientObjects);
  // TryToOverrideFunction("_CrtDumpMemoryLeaks", (uptr)_CrtDumpMemoryLeaks);
  // TryToOverrideFunction("_CrtGetAllocHook", (uptr)_CrtGetAllocHook);
  // TryToOverrideFunction("_CrtGetDumpClient", (uptr)_CrtGetDumpClient);
  // TryToOverrideFunction("_CrtIsMemoryBlock", (uptr)_CrtIsMemoryBlock);
  // TryToOverrideFunction("_CrtIsValidHeapPointer",
  // (uptr)_CrtIsValidHeapPointer); TryToOverrideFunction("_CrtIsValidPointer",
  // (uptr)_CrtIsValidPointer); TryToOverrideFunction("_CrtMemCheckpoint",
  // (uptr)_CrtMemCheckpoint); TryTo OverrideFunction("_CrtMemDifference",
  // (uptr)_CrtMemDifference);
  // TryToOverrideFunction("_CrtMemDumpAllObjectsSince",
  //                      (uptr)_CrtMemDumpAllObjectsSince);
  // TryToOverrideFunction("_CrtMemDumpStatistics",
  // (uptr)_CrtMemDumpStatistics); TryToOverrideFunction("_CrtReportBlockType",
  // (uptr)_CrtReportBlockType); TryToOverrideFunction("_CrtSetAllocHook",
  // (uptr)_CrtSetAllocHook); TryToOverrideFunction("_CrtSetBreakAlloc",
  // (uptr)_CrtSetBreakAlloc); TryToOverrideFunction("_CrtSetDbgBlockType",
  // (uptr)_CrtSetDbgBlockType); TryToOverrideFunction("_CrtSetDbgFlag",
  // (uptr)_CrtSetDbgFlag); TryToOverrideFunction("_CrtSetDumpClient",
  // (uptr)_CrtSetDumpClient);

  // Malloc and calloc are intercepted above rather than by each individual
  // runtime that is present. Allocations that take place prior to asan
  // initialization will either be transferred to asan ownership after a change
  // to that allocation (like reallocating), or it will be freed.
  OverrideFunctionsForEachCrt();

  if (flags()->windows_hook_legacy_allocators) {
    INTERCEPT_FUNCTION(GlobalAlloc);
    INTERCEPT_FUNCTION(GlobalFree);
    INTERCEPT_FUNCTION(GlobalSize);
    INTERCEPT_FUNCTION(GlobalReAlloc);
    INTERCEPT_FUNCTION(GlobalLock);
    INTERCEPT_FUNCTION(GlobalUnlock);
    INTERCEPT_FUNCTION(GlobalHandle);
    INTERCEPT_FUNCTION(GlobalFlags);

    INTERCEPT_FUNCTION(LocalAlloc);
    INTERCEPT_FUNCTION(LocalFree);
    INTERCEPT_FUNCTION(LocalSize);
    INTERCEPT_FUNCTION(LocalReAlloc);
    INTERCEPT_FUNCTION(LocalLock);
    INTERCEPT_FUNCTION(LocalUnlock);
    INTERCEPT_FUNCTION(LocalFlags);

    // LocalHandle symbol is not always available.
    __interception::OverrideFunction("LocalHandle", (uptr)WRAP(LocalHandle),
                                     (uptr *)&REAL(LocalHandle));
  }

  // Undocumented functions must be intercepted by name, not by symbol.
  __interception::OverrideFunction("RtlSizeHeap", (uptr)WRAP(RtlSizeHeap),
                                   (uptr *)&REAL(RtlSizeHeap));
  __interception::OverrideFunction("RtlValidateHeap",
                                   (uptr)WRAP(RtlValidateHeap),
                                   (uptr *)&REAL(RtlValidateHeap));
  __interception::OverrideFunction("RtlFreeHeap", (uptr)WRAP(RtlFreeHeap),
                                   (uptr *)&REAL(RtlFreeHeap));
  __interception::OverrideFunction("RtlReAllocateHeap",
                                   (uptr)WRAP(RtlReAllocateHeap),
                                   (uptr *)&REAL(RtlReAllocateHeap));
  __interception::OverrideFunction("RtlAllocateHeap",
                                   (uptr)WRAP(RtlAllocateHeap),
                                   (uptr *)&REAL(RtlAllocateHeap));
  __interception::OverrideFunction("RtlDestroyHeap", (uptr)WRAP(RtlDestroyHeap),
                                   (uptr *)&REAL(RtlDestroyHeap));
}
}  // namespace __asan

#endif  // _WIN32
