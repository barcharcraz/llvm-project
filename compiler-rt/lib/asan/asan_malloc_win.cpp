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
// Windows-specific malloc interception.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS
#include "asan_allocator.h"
#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_stack.h"
#include "interception/interception.h"

// Intentionally not including windows.h here, to avoid the risk of
// pulling in conflicting declarations of these functions. (With mingw-w64,
// there's a risk of windows.h pulling in stdint.h.)
typedef int BOOL;
typedef void *HANDLE;
typedef const void *LPCVOID;
typedef void *LPVOID;
typedef HANDLE HWND;
typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;
typedef unsigned int UINT;

typedef unsigned long DWORD;
constexpr unsigned long HEAP_ZERO_MEMORY = 0x00000008;
constexpr unsigned long HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
constexpr unsigned long HEAP_ALLOCATE_SUPPORTED_FLAGS = (HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_ALLOCATE_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);
constexpr unsigned long HEAP_FREE_SUPPORTED_FLAGS = (0);
constexpr unsigned long HEAP_FREE_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);
constexpr unsigned long HEAP_REALLOC_SUPPORTED_FLAGS =
    (HEAP_REALLOC_IN_PLACE_ONLY | HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_REALLOC_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);

extern "C" {
LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, size_t dwBytes);
LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem,
                          size_t dwBytes);
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
size_t WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);

BOOL WINAPI HeapValidate(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
HANDLE WINAPI GetProcessHeap();

_declspec(dllimport) HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HGLOBAL WINAPI GlobalFree(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalSize(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI
    GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
_declspec(dllimport) HGLOBAL WINAPI GlobalLock(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalUnlock(HGLOBAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HLOCAL WINAPI LocalFree(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalSize(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI
    LocalReAlloc(HLOCAL hMem, size_t dwBytes, UINT uFlags);
_declspec(dllimport) HLOCAL WINAPI LocalLock(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalUnlock(HLOCAL hMem);
}

using namespace __asan;

// MT: Simply defining functions with the same signature in *.obj
// files overrides the standard functions in the CRT.
// MD: Memory allocation functions are defined in the CRT .dll,
// so we have to intercept them before they are called for the first time.

#if ASAN_DYNAMIC
# define ALLOCATION_FUNCTION_ATTRIBUTE
#else
# define ALLOCATION_FUNCTION_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE
#endif

extern "C" {
ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize(void *ptr) {
  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(ptr, pc, bp);
}

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize_base(void *ptr) {
  return _msize(ptr);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void free(void *ptr) {
  GET_STACK_TRACE_FREE;
  return asan_free(ptr, &stack, FROM_MALLOC);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_base(void *ptr) {
  free(ptr);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *malloc(size_t size) {
  GET_STACK_TRACE_MALLOC;
  return asan_malloc(size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_malloc_base(size_t size) {
  return malloc(size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *calloc(size_t nmemb, size_t size) {
  GET_STACK_TRACE_MALLOC;
  return asan_calloc(nmemb, size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_base(size_t nmemb, size_t size) {
  return calloc(nmemb, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_impl(size_t nmemb, size_t size, int *errno_tmp) {
  return calloc(nmemb, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *realloc(void *ptr, size_t size) {
  GET_STACK_TRACE_MALLOC;
  if (!__asan::flags()->allocator_frees_and_returns_null_on_realloc_zero)
    Report("WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to FALSE."
          " This is not consistent with libcmt/ucrt/msvcrt behavior.");
  return asan_realloc(ptr, size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_realloc_base(void *ptr, size_t size) {
  return realloc(ptr, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc(void *p, size_t n, size_t elem_size) {
  if (!p)
    return calloc(n, elem_size);
  const size_t size = n * elem_size;
  if (elem_size != 0 && size / elem_size != n)
    return 0;

  size_t old_size = _msize(p);
  void *new_alloc = malloc(size);
  if (new_alloc) {
    REAL(memcpy)(new_alloc, p, Min<size_t>(size, old_size));
    if (old_size < size)
      REAL(memset)(static_cast<u8*>(new_alloc) + old_size, 0, size - old_size);
    free(p);
  }
  return new_alloc;
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc_base(void *p, size_t n, size_t elem_size) {
  return _recalloc(p, n, elem_size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_expand(void *memblock, size_t size) {
  // _expand is used in realloc-like functions to resize the buffer if possible.
  // We don't want memory to stand still while resizing buffers, so return 0.
  return 0;
}

#ifdef _DEBUG
ALLOCATION_FUNCTION_ATTRIBUTE
void *_malloc_dbg(size_t size, int, const char *, int) {
  return malloc(size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_dbg(void *ptr, int) {
  free(ptr);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_expand_dbg(void *memblock, size_t size) {
  return _expand(memblock, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_dbg(size_t nmemb, size_t size, int, const char *, int) {
  return calloc(nmemb, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_realloc_dbg(void *ptr, size_t size, int) { return realloc(ptr, size); }

ALLOCATION_FUNCTION_ATTRIBUTE
void *_recalloc_dbg(void *userData, size_t num, size_t size, int, const char *,
                    int) {
  return _recalloc(userData, num, size);
}
#endif //_DEBUG
ALLOCATION_FUNCTION_ATTRIBUTE void *_aligned_malloc(size_t size,
                                                    size_t alignment) {
  GET_STACK_TRACE_MALLOC;
  return asan_memalign(alignment, size, &stack, FROM_MALLOC);
}

ALLOCATION_FUNCTION_ATTRIBUTE void _aligned_free(void *memblock) {
  GET_STACK_TRACE_MALLOC;
  asan_free(memblock, &stack, FROM_MALLOC);
}

ALLOCATION_FUNCTION_ATTRIBUTE size_t _aligned_msize(void *memblock,
                                                    size_t alignment,
                                                    size_t offset) {
  // get the original pointer from the breadcrumb
  GET_CURRENT_PC_BP;
  return asan_malloc_usable_size(memblock, pc, bp);
}

ALLOCATION_FUNCTION_ATTRIBUTE void *_aligned_realloc(void *memblock,
                                                     size_t size,
                                                     size_t alignment) {
  // msdn documentation states that if memblock is nullptr,
  // this should just allocate a new block.
  // if size is 0, the block should be freed and nullptr returned.
  GET_STACK_TRACE_MALLOC;
  if (size == 0 && memblock != nullptr) {
    asan_free(memblock, &stack, FROM_MALLOC);
    return nullptr;
  }

  void *new_ptr = asan_memalign(alignment, size, &stack, FROM_MALLOC);
  if (new_ptr && memblock) {
    GET_CURRENT_PC_BP;
    size_t aligned_size = asan_malloc_usable_size(memblock, pc, bp);
    internal_memcpy(new_ptr, memblock, Min<size_t>(aligned_size, size));
    asan_free(memblock, &stack, FROM_MALLOC);
  }

  return new_ptr;
}

ALLOCATION_FUNCTION_ATTRIBUTE void *_aligned_recalloc(void *memblock,
                                                      size_t size,
                                                      size_t alignment) {
  size_t old_size = 0;
  if (memblock) {
    old_size = _aligned_msize(memblock, alignment, 0);
  }
  void *new_ptr = _aligned_realloc(memblock, size, alignment);
  if (new_ptr && old_size < size) {
    REAL(memset)(static_cast<u8*>(new_ptr) + old_size, 0, size - old_size);
  }
  return new_ptr;
}

int _CrtDbgReport(int, const char*, int,
                  const char*, const char*, ...) {
  ShowStatsAndAbort();
}

int _CrtDbgReportW(int reportType, const wchar_t*, int,
                   const wchar_t*, const wchar_t*, ...) {
  ShowStatsAndAbort();
}

int _CrtSetReportMode(int, int) {
  return 0;
}
}  // extern "C"

#define OWNED_BY_RTL(heap, memory) \
  (!__sanitizer_get_ownership(memory) && HeapValidate(heap, 0, memory))

INTERCEPTOR_WINAPI(size_t, HeapSize, HANDLE hHeap, DWORD dwFlags,
                   LPCVOID lpMem) {
  // If the RTL allocators are hooked we need to check whether the ASAN
  // allocator owns the pointer we're about to use. Allocations occur before
  // interception takes place, so if it is not owned by the RTL heap we can
  // pass it to the ASAN heap for inspection.
  if (flags()->windows_hook_rtl_allocators) {
    if (!asan_inited || OWNED_BY_RTL(hHeap, lpMem))
      return REAL(HeapSize)(hHeap, dwFlags, lpMem);
  } else {
    CHECK(dwFlags == 0 && "unsupported heap flags");
  }
  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(lpMem, pc, bp);
}

INTERCEPTOR_WINAPI(LPVOID, HeapAlloc, HANDLE hHeap, DWORD dwFlags,
                   size_t dwBytes) {
  // If the ASAN runtime is not initialized, or we encounter an unsupported
  // flag, fall back to the original allocator.
  if (flags()->windows_hook_rtl_allocators) {
    if (UNLIKELY(!asan_inited ||
                 (dwFlags & HEAP_ALLOCATE_UNSUPPORTED_FLAGS) != 0)) {
      return REAL(HeapAlloc)(hHeap, dwFlags, dwBytes);
    }
  } else {
    // In the case that we don't hook the rtl allocators,
    // this becomes an assert since there is no failover to the original
    // allocator.
    CHECK((HEAP_ALLOCATE_UNSUPPORTED_FLAGS & dwFlags) != 0 &&
          "unsupported flags");
  }
  GET_STACK_TRACE_MALLOC;
  void *p = asan_malloc(dwBytes, &stack);
  // Reading MSDN suggests that the *entire* usable allocation is zeroed out.
  // Otherwise it is difficult to HeapReAlloc with HEAP_ZERO_MEMORY.
  // https://blogs.msdn.microsoft.com/oldnewthing/20120316-00/?p=8083
  if (p && (dwFlags & HEAP_ZERO_MEMORY)) {
    GET_CURRENT_PC_BP_SP;
    (void)sp;
    auto usable_size = asan_malloc_usable_size(p, pc, bp);
    internal_memset(p, 0, usable_size);
  }
  return p;
}

INTERCEPTOR_WINAPI(BOOL, HeapFree, HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
  // Heap allocations happen before this function is hooked, so we must fall
  // back to the original function if the pointer is not from the ASAN heap,
  // or unsupported flags are provided.
  if (flags()->windows_hook_rtl_allocators) {
    if (OWNED_BY_RTL(hHeap, lpMem))
      return REAL(HeapFree)(hHeap, dwFlags, lpMem);
  } else {
    CHECK((HEAP_FREE_UNSUPPORTED_FLAGS & dwFlags) != 0 && "unsupported flags");
  }
  GET_STACK_TRACE_FREE;
  asan_free(lpMem, &stack, FROM_MALLOC);
  return true;
}

namespace __asan {
using AllocFunction = LPVOID(WINAPI *)(HANDLE, DWORD, size_t);
using ReAllocFunction = LPVOID(WINAPI *)(HANDLE, DWORD, LPVOID, size_t);
using SizeFunction = size_t(WINAPI *)(HANDLE, DWORD, LPVOID);
using FreeFunction = BOOL(WINAPI *)(HANDLE, DWORD, LPVOID);

void *SharedReAlloc(ReAllocFunction reallocFunc, SizeFunction heapSizeFunc,
                    FreeFunction freeFunc, AllocFunction allocFunc,
                    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, size_t dwBytes) {
  CHECK(reallocFunc && heapSizeFunc && freeFunc && allocFunc);
  GET_STACK_TRACE_MALLOC;
  GET_CURRENT_PC_BP_SP;
  (void)sp;
  if (flags()->windows_hook_rtl_allocators) {
    enum AllocationOwnership { NEITHER = 0, ASAN = 1, RTL = 2 };
    AllocationOwnership ownershipState;
    bool owned_rtlalloc = false;
    bool owned_asan = __sanitizer_get_ownership(lpMem);

    if (!owned_asan)
      owned_rtlalloc = HeapValidate(hHeap, 0, lpMem);

    if (owned_asan && !owned_rtlalloc)
      ownershipState = ASAN;
    else if (!owned_asan && owned_rtlalloc)
      ownershipState = RTL;
    else if (!owned_asan && !owned_rtlalloc)
      ownershipState = NEITHER;

    // If this heap block which was allocated before the ASAN
    // runtime came up, use the real HeapFree function.
    if (UNLIKELY(!asan_inited)) {
      return reallocFunc(hHeap, dwFlags, lpMem, dwBytes);
    }
    bool only_asan_supported_flags =
        (HEAP_REALLOC_UNSUPPORTED_FLAGS & dwFlags) == 0;

    if (ownershipState == RTL ||
        (ownershipState == NEITHER && !only_asan_supported_flags)) {
      if (only_asan_supported_flags) {
        // if this is a conversion to ASAN upported flags, transfer this
        // allocation to the ASAN allocator
        void *replacement_alloc;
        if (dwFlags & HEAP_ZERO_MEMORY)
          replacement_alloc = asan_calloc(1, dwBytes, &stack);
        else
          replacement_alloc = asan_malloc(dwBytes, &stack);
        if (replacement_alloc) {
          size_t old_size = heapSizeFunc(hHeap, dwFlags, lpMem);
          if (old_size == ((size_t)0) - 1) {
            asan_free(replacement_alloc, &stack, FROM_MALLOC);
            return nullptr;
          }
          REAL(memcpy)(replacement_alloc, lpMem, old_size);
          freeFunc(hHeap, dwFlags, lpMem);
        }
        return replacement_alloc;
      } else {
        // owned by rtl or neither with unsupported ASAN flags,
        // just pass back to original allocator
        CHECK(ownershipState == RTL || ownershipState == NEITHER);
        CHECK(!only_asan_supported_flags);
        return reallocFunc(hHeap, dwFlags, lpMem, dwBytes);
      }
    }

    if (ownershipState == ASAN && !only_asan_supported_flags) {
      // Conversion to unsupported flags allocation,
      // transfer this allocation back to the original allocator.
      void *replacement_alloc = allocFunc(hHeap, dwFlags, dwBytes);
      size_t old_usable_size = 0;
      if (replacement_alloc) {
        old_usable_size = asan_malloc_usable_size(lpMem, pc, bp);
        REAL(memcpy)(replacement_alloc, lpMem,
                     Min<size_t>(dwBytes, old_usable_size));
        asan_free(lpMem, &stack, FROM_MALLOC);
      }
      return replacement_alloc;
    }

    CHECK((ownershipState == ASAN || ownershipState == NEITHER) &&
          only_asan_supported_flags);
    // At this point we should either be ASAN owned with ASAN supported flags
    // or we owned by neither and have supported flags.
    // Pass through even when it's neither since this could be a null realloc or
    // UAF that ASAN needs to catch.
  } else {
    CHECK((HEAP_REALLOC_UNSUPPORTED_FLAGS & dwFlags) != 0 &&
          "unsupported flags");
  }
  // asan_realloc will never reallocate in place, so for now this flag is
  // unsupported until we figure out a way to fake this.
  if (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY)
    return nullptr;

  // HeapReAlloc and HeapAlloc both happily accept 0 sized allocations.
  // passing a 0 size into asan_realloc will free the allocation.
  // To avoid this and keep behavior consistent, fudge the size if 0.
  // (asan_malloc already does this)
  if (dwBytes == 0)
    dwBytes = 1;

  size_t old_size;
  if (dwFlags & HEAP_ZERO_MEMORY)
    old_size = asan_malloc_usable_size(lpMem, pc, bp);

  void *ptr = asan_realloc(lpMem, dwBytes, &stack);
  if (ptr == nullptr)
    return nullptr;

  if (dwFlags & HEAP_ZERO_MEMORY) {
    size_t new_size = asan_malloc_usable_size(ptr, pc, bp);
    if (old_size < new_size)
      REAL(memset)(((u8 *)ptr) + old_size, 0, new_size - old_size);
  }

  return ptr;
}
}  // namespace __asan

INTERCEPTOR_WINAPI(LPVOID, HeapReAlloc, HANDLE hHeap, DWORD dwFlags,
                   LPVOID lpMem, size_t dwBytes) {
  return SharedReAlloc(REAL(HeapReAlloc), (SizeFunction)REAL(HeapSize),
                       REAL(HeapFree), REAL(HeapAlloc), hHeap, dwFlags, lpMem,
                       dwBytes);
}

// The following functions are undocumented and subject to change.
// However, hooking them is necessary to hook Windows heap
// allocations with detours and their definitions are unlikely to change.
// Comments in /minkernel/ntos/rtl/heappublic.c indicate that these functions
// are part of the heap's public interface.
typedef unsigned long LOGICAL;

// This function is documented as part of the Driver Development Kit but *not*
// the Windows Development Kit.
LOGICAL RtlFreeHeap(void* HeapHandle, DWORD Flags,
                            void* BaseAddress);

// This function is documented as part of the Driver Development Kit but *not*
// the Windows Development Kit.
void* RtlAllocateHeap(void* HeapHandle, DWORD Flags, size_t Size);

// This function is completely undocumented.
void*
RtlReAllocateHeap(void* HeapHandle, DWORD Flags, void* BaseAddress,
                  size_t Size);

// This function is completely undocumented.
size_t RtlSizeHeap(void* HeapHandle, DWORD Flags, void* BaseAddress);

INTERCEPTOR_WINAPI(size_t, RtlSizeHeap, HANDLE HeapHandle, DWORD Flags,
                   void* BaseAddress) {
  if (!flags()->windows_hook_rtl_allocators ||
      UNLIKELY(!asan_inited || OWNED_BY_RTL(HeapHandle, BaseAddress))) {
    return REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);
  }
  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(BaseAddress, pc, bp);
}

INTERCEPTOR_WINAPI(BOOL, RtlFreeHeap, HANDLE HeapHandle, DWORD Flags,
                   void* BaseAddress) {
  // Heap allocations happen before this function is hooked, so we must fall
  // back to the original function if the pointer is not from the ASAN heap, or
  // unsupported flags are provided.
  if (!flags()->windows_hook_rtl_allocators ||
      UNLIKELY((HEAP_FREE_UNSUPPORTED_FLAGS & Flags) != 0 ||
               OWNED_BY_RTL(HeapHandle, BaseAddress))) {
    return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
  }
  GET_STACK_TRACE_FREE;
  asan_free(BaseAddress, &stack, FROM_MALLOC);
  return true;
}

INTERCEPTOR_WINAPI(void*, RtlAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   size_t Size) {
  // If the ASAN runtime is not initialized, or we encounter an unsupported
  // flag, fall back to the original allocator.
  if (!flags()->windows_hook_rtl_allocators ||
      UNLIKELY(!asan_inited ||
               (Flags & HEAP_ALLOCATE_UNSUPPORTED_FLAGS) != 0)) {
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }
  GET_STACK_TRACE_MALLOC;
  void *p;
  // Reading MSDN suggests that the *entire* usable allocation is zeroed out.
  // Otherwise it is difficult to HeapReAlloc with HEAP_ZERO_MEMORY.
  // https://blogs.msdn.microsoft.com/oldnewthing/20120316-00/?p=8083
  if (Flags & HEAP_ZERO_MEMORY) {
    p = asan_calloc(Size, 1, &stack);
  } else {
    p = asan_malloc(Size, &stack);
  }
  return p;
}

INTERCEPTOR_WINAPI(void*, RtlReAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   void* BaseAddress, size_t Size) {
  // If it's actually a heap block which was allocated before the ASAN runtime
  // came up, use the real RtlFreeHeap function.
  if (!flags()->windows_hook_rtl_allocators)
    return REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);

  return SharedReAlloc(REAL(RtlReAllocateHeap), REAL(RtlSizeHeap),
                       REAL(RtlFreeHeap), REAL(RtlAllocateHeap), HeapHandle,
                       Flags, BaseAddress, Size);
}

// FIXED and ZEROINIT correspond to LMEM_FIXED/GMEM_FIXED
// and LMEM_ZEROINIT/GMEM_ZEROINIT (as provided in the documentation).
// In case, if these values change then FIXED and ZEROINIT
// will have to be updated accordingly.
#define FIXED 0x0000
#define ZEROINIT 0x0040

constexpr unsigned long SHARED_ALLOC_SUPPORTED_FLAGS = (FIXED | ZEROINIT);
constexpr unsigned long SHARED_ALLOC_UNSUPPORTED_FLAGS =
    (~SHARED_ALLOC_SUPPORTED_FLAGS);

namespace __asan {
  //forward declaring a few items for the shared versions of some of these Global/Local interceptors.
using GlobalLocalAlloc = HANDLE(WINAPI *)(UINT, SIZE_T);
using GlobalLocalRealloc = HANDLE(WINAPI *)(HANDLE, SIZE_T, UINT);
using GlobalLocalSize = SIZE_T(WINAPI *)(HANDLE);
using GlobalLocalFree = HANDLE(WINAPI *)(HANDLE);
using GlobalLocalLock = LPVOID(WINAPI *)(HANDLE);
using GlobalLocalUnlock = LPVOID(WINAPI *)(HANDLE);
HANDLE GlobalLocalGenericFree(GlobalLocalUnlock lockFunction, GlobalLocalFree freeFunction, HANDLE hMem);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalAlloc, UINT uFlags, SIZE_T dwBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & SHARED_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(GlobalAlloc)(uFlags, dwBytes);
  }

  GET_STACK_TRACE_MALLOC;
  if (uFlags & ZEROINIT)
    return asan_calloc(dwBytes, 1, &stack);
  else
    return asan_malloc(dwBytes, &stack);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalFree, HGLOBAL hMem) {
  return GlobalLocalGenericFree(
                              GlobalLock, 
                              REAL(GlobalFree), 
                              hMem);
}

INTERCEPTOR_WINAPI(SIZE_T, GlobalSize, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, so if it is not owned by RTL heap, the we can
  // pass it to ASAN heap for inspection.
  if (!asan_inited || OWNED_BY_RTL(GetProcessHeap(), hMem))
    return REAL(GlobalSize)(hMem);

  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(hMem, pc, bp);
}

namespace __asan {

enum class AllocationOwnership {
  OWNED_BY_UNKNOWN,
  OWNED_BY_ASAN,
  OWNED_BY_RTL,
  OWNED_BY_GLOBAL_OR_LOCAL,
  OWNED_BY_GLOBAL_OR_LOCAL_HANDLE,
};

HANDLE GlobalLocalGenericFree(GlobalLocalUnlock lockFunction, GlobalLocalFree freeFunction, HANDLE hMem) {
// If the memory we are trying to free is not owned
  // by ASan heap, then fall back to the original GlobalFree.
  if (!__sanitizer_get_ownership(hMem)) {
    HGLOBAL pointer = lockFunction(hMem);
    if (pointer != nullptr) {
      //This was either a handle, or it was a pointer to begin with.
      // Either way, we can HeapValidate now.
       if (HeapValidate(GetProcessHeap(), 0, pointer)) {
        return freeFunction(hMem);
      }
    }
  }
  // Now we're either 
  // a) an asan-owned pointer
  // b) an invalid pointer which asan needs to report on.
 
  GET_STACK_TRACE_FREE;
  asan_free(hMem, &stack, FROM_MALLOC);
  return nullptr;
}

void *RtlToAsan(void *mPtr, size_t old_size, size_t dwBytes,
                GlobalLocalFree freeFunc, BufferedStackTrace *stack) {
  // Transfer from RTL owned allocation to ASAN owned allocation
  void *replacement_alloc;
  replacement_alloc = asan_calloc(dwBytes, 1, stack);
  if (replacement_alloc) {
    if (old_size == ((SIZE_T)0) - 1) {
      asan_free(replacement_alloc, stack, FROM_MALLOC);
      return nullptr;
    }
    REAL(memcpy)(replacement_alloc, mPtr, old_size);
    freeFunc((HANDLE)mPtr);
  }
  return replacement_alloc;
}

void *AsanToRtl(void *mPtr, UINT uFlags, SIZE_T dwBytes,
                GlobalLocalAlloc allocFunc, GlobalLocalLock lockFunc,
                GlobalLocalLock unlockFunc, BufferedStackTrace *stack, uptr pc,
                uptr bp) {
  // Transfer from ASAN owned allocation to RTL owned allocation
  void *replacement_alloc;
  HANDLE mem = allocFunc(uFlags, dwBytes);
  // GlobalLock/LocalLock return a pointer to the memory owned by the mem
  // handle. We need the pointer to copy the data over from the ASAN owned
  // memory.
  replacement_alloc = (void *)lockFunc(mem);
  size_t old_usable_size = 0;
  if (replacement_alloc) {
    old_usable_size = asan_malloc_usable_size(mPtr, pc, bp);
    REAL(memcpy)(replacement_alloc, mPtr, Min<size_t>(dwBytes, old_usable_size));
    asan_free(mPtr, stack, FROM_MALLOC);
  }
  unlockFunc(mem);
  return replacement_alloc;
}

void *ReAllocToAsan(UINT uFlags, void *mPtr, size_t dwBytes, uptr pc, uptr bp,
                    BufferedStackTrace *stack) {
  // GlobalAlloc, LocalAlloc, GlocalReAlloc and LocalReAlloc all
  // accept 0 sized allocations. Passing a zero size into asan_realloc will
  // free the allocation. To avoid this and keep behavior consistent, fudge
  // the size if zero (asan_malloc already does this).
  if (dwBytes == 0)
    dwBytes = 1;

  size_t old_size;
  if (uFlags & ZEROINIT)
    old_size = asan_malloc_usable_size(mPtr, pc, bp);

  void *ptr = asan_realloc(mPtr, dwBytes, stack);
  if (ptr == nullptr)
    return nullptr;

  if (uFlags & ZEROINIT) {
    size_t new_size = asan_malloc_usable_size(ptr, pc, bp);
    if (old_size < new_size)
      REAL(memset)(((u8 *)ptr) + old_size, 0, new_size - old_size);
  }
  return ptr;
}

AllocationOwnership CheckGlobalLocalHeapOwnership(
    HANDLE hMem, GlobalLocalLock lockFunc, GlobalLocalUnlock unlockFunc) {
  /*  To figure the validity of hMem, we use GlobalLock/LocalLock. Those two
   * functions can return three things: (1) the pointer that's passed in, in
   * which case it is a pointer owned by the Global/Local heap (2) the pointer
   * to the allocated object if it's a Global/Local heap HANDLE (3) nullptr if it's
   * a pointer which does not belong to the Global/Local heap Using these three
   * return types, we figure out if the pointer is TYPE_VALID_PTR or TYPE_HANDLE
   * or TYPE_UNKNOWN_PTR
   *
   * NOTE: As an implementation detail, movable memory objects also live on the
   * heap. HeapValidate will return true if given a moveable memory handle.
   *
   */

  // Do this first to avoid expensive checks if the pointer is owned by ASAN.
  if (__sanitizer_get_ownership(hMem)) {
    return AllocationOwnership::OWNED_BY_ASAN;
  }

  // It is not safe to pass wild pointers to GlobalLock/LocalLock.
  if (HeapValidate(GetProcessHeap(), 0, hMem)) {
    void *ptr = lockFunc(hMem);
    // We don't care whether ptr is moved after this point as we're just trying
    // to determine where it came from.
    unlockFunc(hMem);
    if (ptr == hMem) {
      return AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL;
    } else if (ptr != nullptr) {
      return AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE;
    }
  }
  return AllocationOwnership::OWNED_BY_UNKNOWN;
}

void *ReAllocGlobalLocal(GlobalLocalRealloc reallocFunc,
                         GlobalLocalSize sizeFunc, GlobalLocalFree freeFunc,
                         GlobalLocalAlloc allocFunc, GlobalLocalLock lockFunc,
                         GlobalLocalUnlock unlockFunc, HANDLE hMem,
                         DWORD dwBytes, UINT uFlags) {
  CHECK(reallocFunc && sizeFunc && freeFunc && allocFunc);
  GET_STACK_TRACE_MALLOC;
  GET_CURRENT_PC_BP_SP;
  (void)sp;

  bool only_asan_supported_flags =
      (SHARED_ALLOC_UNSUPPORTED_FLAGS & uFlags) == 0;

  AllocationOwnership ownershipState =
      CheckGlobalLocalHeapOwnership(hMem, lockFunc, unlockFunc);

  // If this global block which was allocated before the ASAN
  // runtime came up OR if mPtr is invalid, use the real GlobalReAlloc function.
  if (UNLIKELY(!asan_inited) ||
      ownershipState == AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE) {
    return reallocFunc(hMem, dwBytes, uFlags);
  }

  // Since hMem is not a handle to moveable memory we may safely cast it to
  // pointer.
  void *mPtr = (void *)hMem;

  if (ownershipState == AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL ||
      (ownershipState == AllocationOwnership::OWNED_BY_UNKNOWN &&
       !only_asan_supported_flags)) {
    if (only_asan_supported_flags) {
      // if this is a conversion to ASAN supported flags, transfer this
      // allocation to the ASAN allocator
      return RtlToAsan(mPtr, sizeFunc(mPtr), dwBytes, freeFunc, &stack);
    } else {
      // owned by this heap or neither with unsupported ASAN flags,
      // just pass back to original allocator
      CHECK(ownershipState == AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL ||
            ownershipState == AllocationOwnership::OWNED_BY_UNKNOWN);
      CHECK(!only_asan_supported_flags);
      return reallocFunc(mPtr, dwBytes, uFlags);
    }
  }

  if (ownershipState == AllocationOwnership::OWNED_BY_ASAN &&
      !only_asan_supported_flags) {
    // Conversion to unsupported flags allocation,
    // transfer this allocation back to the original allocator.
    return AsanToRtl(mPtr, uFlags, dwBytes, allocFunc, lockFunc, unlockFunc,
                     &stack, pc, bp);
  }

  CHECK((ownershipState == AllocationOwnership::OWNED_BY_ASAN ||
         ownershipState == AllocationOwnership::OWNED_BY_RTL ||
         ownershipState == AllocationOwnership::OWNED_BY_UNKNOWN) &&
        only_asan_supported_flags);

  return ReAllocToAsan(uFlags, mPtr, dwBytes, pc, bp, &stack);
}
}  // namespace __asan

INTERCEPTOR_WINAPI(HGLOBAL, GlobalReAlloc, HGLOBAL hMem, DWORD dwBytes,
                   UINT uFlags) {
  return ReAllocGlobalLocal(
      (GlobalLocalRealloc)REAL(GlobalReAlloc),
      (GlobalLocalSize)REAL(GlobalSize), (GlobalLocalFree)REAL(GlobalFree),
      (GlobalLocalAlloc)REAL(GlobalAlloc), (GlobalLocalLock)GlobalLock,
      (GlobalLocalUnlock)GlobalUnlock, (HANDLE)hMem, dwBytes, uFlags);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalAlloc, UINT uFlags, SIZE_T uBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & SHARED_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(LocalAlloc)(uFlags, uBytes);
  }

  GET_STACK_TRACE_MALLOC;
  if (uFlags & ZEROINIT)
    return asan_calloc(uBytes, 1, &stack);
  else
    return asan_malloc(uBytes, &stack);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalFree, HGLOBAL hMem) {
  // If the memory we are trying to free is not owned
  // ASan heap, then fall back to the original LocalFree.
  return GlobalLocalGenericFree(LocalLock, REAL(LocalFree), hMem);
}

INTERCEPTOR_WINAPI(SIZE_T, LocalSize, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, so if it is not owned by RTL heap, the we can
  // pass it to ASAN heap for inspection.
  if (!asan_inited || OWNED_BY_RTL(GetProcessHeap(), hMem))
    return REAL(LocalSize)(hMem);

  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(hMem, pc, bp);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalReAlloc, HGLOBAL hMem, DWORD dwBytes,
                   UINT uFlags) {
  return ReAllocGlobalLocal(
      (GlobalLocalRealloc)REAL(LocalReAlloc), (GlobalLocalSize)REAL(LocalSize),
      (GlobalLocalFree)REAL(LocalFree), (GlobalLocalAlloc)REAL(LocalAlloc),
      (GlobalLocalLock)LocalLock, (GlobalLocalUnlock)LocalUnlock, (HANDLE)hMem,
      dwBytes, uFlags);
}

namespace __asan {

static void TryToOverrideFunction(const char *fname, uptr new_func) {
  // Failure here is not fatal. The CRT may not be present, and different CRT
  // versions use different symbols.
  if (!__interception::OverrideFunction(fname, new_func))
    VPrintf(2, "Failed to override function %s\n", fname);
}

void ReplaceSystemMalloc() {
#if defined(ASAN_DYNAMIC)
  TryToOverrideFunction("free", (uptr)free);
  TryToOverrideFunction("_free_base", (uptr)free);
  TryToOverrideFunction("malloc", (uptr)malloc);
  TryToOverrideFunction("_malloc_base", (uptr)malloc);
  TryToOverrideFunction("_malloc_crt", (uptr)malloc);
  TryToOverrideFunction("calloc", (uptr)calloc);
  TryToOverrideFunction("_calloc_base", (uptr)calloc);
  TryToOverrideFunction("_calloc_crt", (uptr)calloc);
  TryToOverrideFunction("realloc", (uptr)realloc);
  TryToOverrideFunction("_realloc_base", (uptr)realloc);
  TryToOverrideFunction("_realloc_crt", (uptr)realloc);
  TryToOverrideFunction("_recalloc", (uptr)_recalloc);
  TryToOverrideFunction("_recalloc_base", (uptr)_recalloc);
  TryToOverrideFunction("_recalloc_crt", (uptr)_recalloc);
  TryToOverrideFunction("_msize", (uptr)_msize);
  TryToOverrideFunction("_msize_base", (uptr)_msize);
  TryToOverrideFunction("_expand", (uptr)_expand);
  TryToOverrideFunction("_expand_base", (uptr)_expand);
  TryToOverrideFunction("_aligned_malloc", (uptr)_aligned_malloc);
  TryToOverrideFunction("_aligned_msize", (uptr)_aligned_msize);
  TryToOverrideFunction("_aligned_free", (uptr)_aligned_free);
  TryToOverrideFunction("_aligned_realloc", (uptr)_aligned_realloc);
#ifdef _DEBUG
  TryToOverrideFunction("_expand_dbg", (uptr)_expand_dbg);
  TryToOverrideFunction("_free_dbg", (uptr)_free_dbg);
  TryToOverrideFunction("_malloc_dbg", (uptr)_malloc_dbg);
  TryToOverrideFunction("_calloc_dbg", (uptr)_calloc_dbg);
  TryToOverrideFunction("_realloc_dbg", (uptr)_realloc_dbg);
  TryToOverrideFunction("_recalloc_dbg", (uptr)_recalloc_dbg);
#endif
  if (flags()->windows_hook_rtl_allocators) {
    INTERCEPT_FUNCTION(GlobalAlloc);
    INTERCEPT_FUNCTION(GlobalFree);
    INTERCEPT_FUNCTION(GlobalSize);
    INTERCEPT_FUNCTION(GlobalReAlloc);
    INTERCEPT_FUNCTION(LocalAlloc);
    INTERCEPT_FUNCTION(LocalFree);
    INTERCEPT_FUNCTION(LocalSize);
    INTERCEPT_FUNCTION(LocalReAlloc);

    INTERCEPT_FUNCTION(HeapSize);
    INTERCEPT_FUNCTION(HeapFree);
    INTERCEPT_FUNCTION(HeapReAlloc);
    INTERCEPT_FUNCTION(HeapAlloc);

    // Undocumented functions must be intercepted by name, not by symbol.
    __interception::OverrideFunction("RtlSizeHeap", (uptr)WRAP(RtlSizeHeap),
                                     (uptr *)&REAL(RtlSizeHeap));
    __interception::OverrideFunction("RtlFreeHeap", (uptr)WRAP(RtlFreeHeap),
                                     (uptr *)&REAL(RtlFreeHeap));
    __interception::OverrideFunction("RtlReAllocateHeap",
                                     (uptr)WRAP(RtlReAllocateHeap),
                                     (uptr *)&REAL(RtlReAllocateHeap));
    __interception::OverrideFunction("RtlAllocateHeap",
                                     (uptr)WRAP(RtlAllocateHeap),
                                     (uptr *)&REAL(RtlAllocateHeap));
  } else {
#ifdef _DEBUG
#define UCRT_LIBNAME "ucrtbased.dll"
#else
#define UCRT_LIBNAME "ucrtbase.dll"
#endif
#define INTERCEPT_UCRT_FUNCTION(func)                                  \
  if (!INTERCEPT_FUNCTION_DLLIMPORT(                                   \
          UCRT_LIBNAME, "api-ms-win-core-heap-l1-1-0.dll", func)) {    \
    VPrintf(2, "Failed to intercept ucrtbase.dll import %s\n", #func); \
  }
    INTERCEPT_UCRT_FUNCTION(HeapAlloc);
    INTERCEPT_UCRT_FUNCTION(HeapFree);
    INTERCEPT_UCRT_FUNCTION(HeapReAlloc);
    INTERCEPT_UCRT_FUNCTION(HeapSize);
#undef INTERCEPT_UCRT_FUNCTION
  }
#endif  // defined(ASAN_DYNAMIC)
}
}  // namespace __asan

#endif  // _WIN32
