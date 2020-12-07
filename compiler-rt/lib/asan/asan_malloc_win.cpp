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

#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS
#include "asan_allocator.h"
#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_malloc_win_moveable.h"
#include "asan_stack.h"
#include "asan_win_immortalize.h"
#include "asan_win_scoped_lock.h"
#include "interception/interception.h"

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

constexpr unsigned long HEAP_NO_SERIALIZE = 0x00000001;
constexpr unsigned long HEAP_GENERATE_EXCEPTIONS = 0x00000004;
constexpr unsigned long HEAP_ZERO_MEMORY = 0x00000008;
constexpr unsigned long HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
constexpr unsigned long HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;

constexpr unsigned long HEAP_ALLOCATE_SUPPORTED_FLAGS =
    (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_ALLOCATE_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);

constexpr unsigned long HEAP_REALLOC_SUPPORTED_FLAGS =
    (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY);
constexpr unsigned long HEAP_REALLOC_UNSUPPORTED_FLAGS =
    (~HEAP_ALLOCATE_SUPPORTED_FLAGS);

extern "C" {
HANDLE WINAPI GetProcessHeap();
BOOL WINAPI HeapValidate(HANDLE, DWORD, void *);

DWORD WINAPI GetCurrentThreadId();

_declspec(dllimport) HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HGLOBAL WINAPI GlobalFree(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalSize(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI
    GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
_declspec(dllimport) HGLOBAL WINAPI GlobalLock(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalUnlock(HGLOBAL hMem);
_declspec(dllimport) HGLOBAL WINAPI GlobalHandle(HGLOBAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T dwBytes);
_declspec(dllimport) HLOCAL WINAPI LocalFree(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalSize(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI
    LocalReAlloc(HLOCAL hMem, size_t dwBytes, UINT uFlags);
_declspec(dllimport) HLOCAL WINAPI LocalLock(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalUnlock(HLOCAL hMem);
_declspec(dllimport) HLOCAL WINAPI LocalHandle(HLOCAL hMem);
}

using namespace __asan;

// MT: Simply defining functions with the same signature in *.obj
// files overrides the standard functions in the CRT.
// MD: Memory allocation functions are defined in the CRT .dll,
// so we have to intercept them before they are called for the first time.

#if ASAN_DYNAMIC
#define ALLOCATION_FUNCTION_ATTRIBUTE
#else
#define ALLOCATION_FUNCTION_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE
#endif

extern "C" {
ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize(void *ptr) {
  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(ptr, pc, bp);
}

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize_base(void *ptr) { return _msize(ptr); }

ALLOCATION_FUNCTION_ATTRIBUTE
void free(void *ptr) {
  GET_STACK_TRACE_FREE;
  return asan_free(ptr, &stack, FROM_MALLOC);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_base(void *ptr) { free(ptr); }

ALLOCATION_FUNCTION_ATTRIBUTE
void *malloc(size_t size) {
  GET_STACK_TRACE_MALLOC;
  return asan_malloc(size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_malloc_base(size_t size) { return malloc(size); }

ALLOCATION_FUNCTION_ATTRIBUTE
void *calloc(size_t nmemb, size_t size) {
  GET_STACK_TRACE_MALLOC;
  return asan_calloc(nmemb, size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_base(size_t nmemb, size_t size) { return calloc(nmemb, size); }

ALLOCATION_FUNCTION_ATTRIBUTE
void *_calloc_impl(size_t nmemb, size_t size, int *errno_tmp) {
  return calloc(nmemb, size);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *realloc(void *ptr, size_t size) {
  GET_STACK_TRACE_MALLOC;
  if (!__asan::flags()->allocator_frees_and_returns_null_on_realloc_zero)
    Report(
        "WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to "
        "FALSE."
        " This is not consistent with libcmt/ucrt/msvcrt behavior.");
  return asan_realloc(ptr, size, &stack);
}

ALLOCATION_FUNCTION_ATTRIBUTE
void *_realloc_base(void *ptr, size_t size) { return realloc(ptr, size); }

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
      REAL(memset)(static_cast<u8 *>(new_alloc) + old_size, 0, size - old_size);
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
void *_malloc_dbg(size_t size, int, const char *, int) { return malloc(size); }

ALLOCATION_FUNCTION_ATTRIBUTE
void _free_dbg(void *ptr, int) { free(ptr); }

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

ALLOCATION_FUNCTION_ATTRIBUTE
size_t _msize_dbg(void *userData, int) { return _msize(userData); }
#endif  //_DEBUG

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
    REAL(memset)(static_cast<u8 *>(new_ptr) + old_size, 0, size - old_size);
  }
  return new_ptr;
}

}  // extern "C"

struct AsanHeapMemoryNode {
  static void *operator new(size_t size) { return InternalAlloc(size); }
  static void operator delete(void *p) { InternalFree(p); }

  AsanHeapMemoryNode(void *_memory) : memory(_memory) {}

  void *memory;
  AsanHeapMemoryNode *next;
};

typedef __sanitizer::IntrusiveList<AsanHeapMemoryNode> AsanMemoryList;
typedef __sanitizer::AddrHashMap<AsanHeapMemoryNode *, 4099> AsanMemoryMap;

struct AsanHeap {
  // This data structure is undocumented and is subject to change.
  struct HEAP {
#if SANITIZER_WORDSIZE == 64
    unsigned long padding[28];
#elif SANITIZER_WORDSIZE == 32
    unsigned long padding[16];
#else
#error "Platform not supported"
#endif
    unsigned long flags;
    unsigned long forceFlags;
  };

  static void *operator new(size_t size) { return InternalAlloc(size); }
  static void *operator new(size_t, void *p) { return p; }
  static void operator delete(void *p) { InternalFree(p); }

  explicit AsanHeap(HANDLE _heap) : heap(*((HEAP *)_heap)) {
    constexpr unsigned long HEAP_PROCESS_CLASS = 0x00000000;
    constexpr unsigned long HEAP_PRIVATE_CLASS = 0x00001000;
    constexpr unsigned long HEAP_CLASS_MASK = 0x0000F000;

    constexpr unsigned long HEAP_SUPPORTED_CLASSES[] =
      {HEAP_PROCESS_CLASS, HEAP_PRIVATE_CLASS};
  
    const unsigned long heapClass =
      (heap.flags | heap.forceFlags) & HEAP_CLASS_MASK;

    bool heapClassSupported = false;
    for (const auto& heapClassType : HEAP_SUPPORTED_CLASSES) {
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

  [[nodiscard]] unsigned long GetFlags() const {
    constexpr unsigned long HEAP_EXAMINED_FLAGS =
      (HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY);

    return (heap.flags | heap.forceFlags) & HEAP_EXAMINED_FLAGS;
  }

  // A reference to some members of the opaque HEAP data structure.
  const HEAP &heap;

  // A lock to keep the accesses to the map and the list atomic.
  __sanitizer::SpinMutex lock = {};

  // We need to keep track of which thread holds the lock if any.
  __sanitizer::atomic_uint32_t thread_id = {};

  // A list of memory managed by asan associated with this heap to enable
  // freeing all memory when a heap is destroyed.
  AsanMemoryList asan_memory = {};

  // A mapping of asan managed pointers to the node before them in the list to
  // allow for efficient removal when freed.
  AsanMemoryMap memory_map;

  bool is_supported;
};

struct AsanHeapMap : public __sanitizer::AddrHashMap<AsanHeap *, 37> {
  using __sanitizer::AddrHashMap<AsanHeap *, 37>::Handle;

  static void *operator new(size_t, void *p) { return p; }
};

AsanHeapMap *GetAsanHeapMap() { return &immortalize<AsanHeapMap>(); }
AsanHeap *GetDefaultHeap() {
  return &immortalize<AsanHeap, void *>(GetProcessHeap());
}

AsanHeap *GetAsanHeap(void *heap) {
  AsanHeap *asan_heap;
  if (heap == GetProcessHeap()) {
    asan_heap = GetDefaultHeap();
  } else {
    AsanHeapMap::Handle h_find_or_create(
        GetAsanHeapMap(), reinterpret_cast<uptr>(heap), false, true);

    if (h_find_or_create.created()) {
      asan_heap = new AsanHeap(heap);
      *h_find_or_create = asan_heap;
    } else {
      asan_heap = *h_find_or_create;
    }
  }

  return asan_heap;
}

AsanHeap *GetAsanHeap(void *heap, unsigned long flags = 0) {
  AsanHeap *asan_heap;
  if (heap == GetProcessHeap()) {
    asan_heap = GetDefaultHeap();
  } else {
    AsanHeapMap::Handle h_find_or_create(
        GetAsanHeapMap(), reinterpret_cast<uptr>(heap), false, true);

    if (h_find_or_create.created()) {
      asan_heap = new AsanHeap(flags);
      *h_find_or_create = asan_heap;
    } else {
      asan_heap = *h_find_or_create;
    }
  }

  return asan_heap;
}

struct AllocationOwnership {
  enum { NEITHER = 0, ASAN = 1, RTL = 2 };
  const int ownership;

  AllocationOwnership(void *heap, void *memory)
      : ownership(get_ownership(heap, memory)) {}

 private:
  int get_ownership(void *heap, void *memory) {
    if (__sanitizer_get_ownership(memory)) {
      return ASAN;
    } else if (HeapValidate(heap, 0, memory)) {
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

#define OWNED_BY_RTL(heap, memory) \
  (!__sanitizer_get_ownership(memory) && HeapValidate(heap, 0, memory))

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

// TODO: This doesn't gracefully handle the situation that one thread is trying
// to use this heap while it is being destroyed.
INTERCEPTOR_WINAPI(void *, RtlDestroyHeap, void *HeapHandle) {
  AsanHeapMap::Handle h_delete(GetAsanHeapMap(),
                               reinterpret_cast<uptr>(HeapHandle), true, false);
  if (UNLIKELY(!h_delete.exists() && HeapHandle != GetProcessHeap())) {
    return REAL(RtlDestroyHeap)(HeapHandle);
  }

  AsanHeap *asan_heap = GetAsanHeap(HeapHandle);

  GET_STACK_TRACE_FREE;
  asan_heap->lock.Lock();

  // Free all memory managed by asan and associated with this heap.
  while (!asan_heap->asan_memory.empty()) {
    asan_free(asan_heap->asan_memory.front()->memory, &stack, FROM_MALLOC);
    delete asan_heap->asan_memory.front();
    asan_heap->asan_memory.pop_front();
  }

  if (HeapHandle != GetProcessHeap()) {
    delete asan_heap;
  }

  return REAL(RtlDestroyHeap)(HeapHandle);
}

INTERCEPTOR_WINAPI(size_t, RtlSizeHeap, HANDLE HeapHandle, DWORD Flags,
                   void *BaseAddress) {
  if (UNLIKELY(!asan_inited || !BaseAddress)) {
    return REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);
  }

  AllocationOwnership owner(HeapHandle, BaseAddress);
  if (UNLIKELY(owner != AllocationOwnership::ASAN)) {
    return REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);
  }

  AsanHeap *asan_heap = GetAsanHeap(HeapHandle);
  {
    // We know that ASAN owns the memory but let's make sure it is owned by
    // this heap.
    AsanMemoryMap::Handle h(&(asan_heap->memory_map),
                            reinterpret_cast<uptr>(BaseAddress), false, false);
    if (!h.exists()) {
      return -1;
    }
  }

  GET_CURRENT_PC_BP_SP;
  (void)sp;
  return asan_malloc_usable_size(BaseAddress, pc, bp);
}

INTERCEPTOR_WINAPI(void *, RtlAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   size_t Size) {
  if (UNLIKELY(!asan_inited)) {
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  AsanHeap *asan_heap = GetAsanHeap(HeapHandle);
  if (UNLIKELY(!asan_heap->is_supported)) {
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  const DWORD all_flags = Flags | asan_heap->GetFlags();
  const DWORD unsupported_flags = all_flags & HEAP_ALLOCATE_UNSUPPORTED_FLAGS;

  if (UNLIKELY(unsupported_flags)) {
    return REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  // Take the lock in the AsanHeap
  RecursiveScopedLock raii_lock(asan_heap->lock, asan_heap->thread_id);

  GET_STACK_TRACE_MALLOC;
  void *p = asan_malloc(Size, &stack);
  // Reading MSDN suggests that the *entire* usable allocation is zeroed out.
  // Otherwise it is difficult to HeapReAlloc with HEAP_ZERO_MEMORY.
  // https://blogs.msdn.microsoft.com/oldnewthing/20120316-00/?p=8083
  if (p && (Flags & HEAP_ZERO_MEMORY)) {
    GET_CURRENT_PC_BP_SP;
    (void)sp;
    auto usable_size = asan_malloc_usable_size(p, pc, bp);
    internal_memset(p, 0, usable_size);
  }

  AsanHeapMemoryNode *mem_node = new AsanHeapMemoryNode(p);
  AsanHeapMemoryNode *prev_tail = asan_heap->asan_memory.back();
  asan_heap->asan_memory.push_back(mem_node);

  {
    AsanMemoryMap::Handle h(&(asan_heap->memory_map), reinterpret_cast<uptr>(p),
                            false, true);
    *h = prev_tail;
  }

  return p;
}

INTERCEPTOR_WINAPI(LOGICAL, RtlFreeHeap, void *HeapHandle, DWORD Flags,
                   void *BaseAddress) {
  if (UNLIKELY(!asan_inited || !BaseAddress)) {
    return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
  }

  AllocationOwnership owner(HeapHandle, BaseAddress);
  if (UNLIKELY(owner == AllocationOwnership::RTL)) {
    return REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
  }

  if (owner == AllocationOwnership::NEITHER) {
    GET_STACK_TRACE_FREE;
    // This should either return double-free or wild pointer errors
    asan_free(BaseAddress, &stack, FROM_MALLOC);

    return false;
  }

  // ASAN owns the memory
  AsanHeap *asan_heap = GetAsanHeap(HeapHandle);

  // Take the lock in the AsanHeap
  RecursiveScopedLock raii_lock(asan_heap->lock, asan_heap->thread_id);

  AsanHeapMemoryNode *found;
  {
    AsanMemoryMap::Handle h_delete(&(asan_heap->memory_map),
                                   reinterpret_cast<uptr>(BaseAddress), true,
                                   false);

    CHECK(h_delete.exists() &&
          "The memory being freed does not belong to this heap.");

    found = *h_delete;
  }

  AsanHeapMemoryNode *remove;
  AsanHeapMemoryNode *update;
  if (found) {
    remove = found->next;
    asan_heap->asan_memory.extract(found, found->next);
    update = found->next;
  } else {
    remove = asan_heap->asan_memory.front();
    asan_heap->asan_memory.pop_front();
    update = asan_heap->asan_memory.front();
  }

  CHECK(remove->memory == BaseAddress &&
        "Memory list is inconsistent with map. "
        "This is a bug, please report it.");

  if (update) {
    {
      AsanMemoryMap::Handle h_update(&(asan_heap->memory_map),
                                     reinterpret_cast<uptr>(update->memory),
                                     true, false);
    }
    {
      AsanMemoryMap::Handle h_update(&(asan_heap->memory_map),
                                     reinterpret_cast<uptr>(update->memory),
                                     false, true);
      *h_update = found;
    }
  }

  delete remove;

  GET_STACK_TRACE_FREE;
  asan_free(BaseAddress, &stack, FROM_MALLOC);

  return true;
}

INTERCEPTOR_WINAPI(void *, RtlReAllocateHeap, HANDLE HeapHandle, DWORD Flags,
                   void *BaseAddress, size_t Size) {
  if (UNLIKELY(!asan_inited)) {
    return REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);
  }

  if (UNLIKELY(!BaseAddress)) {
    return WRAP(RtlAllocateHeap)(HeapHandle, Flags, Size);
  }

  AllocationOwnership owner(HeapHandle, BaseAddress);

  AsanHeap *asan_heap = GetAsanHeap(HeapHandle);
  if (UNLIKELY(!asan_heap->is_supported)) {
    return REAL(RtlReAllocateHeap)(HeapHandle, Flags, BaseAddress, Size);
  }

  const DWORD all_flags = Flags | asan_heap->GetFlags();
  const DWORD asan_unsupported_flags =
      (HEAP_REALLOC_UNSUPPORTED_FLAGS & all_flags);

  // Take the lock in the AsanHeap
  RecursiveScopedLock raii_lock(asan_heap->lock, asan_heap->thread_id);

  GET_STACK_TRACE_MALLOC;
  GET_CURRENT_PC_BP_SP;
  (void)sp;

  void *replacement_alloc;
  size_t old_size;
  if (owner == AllocationOwnership::NEITHER) {
    // This should cause a use-after-free or wild pointer error. If it is a
    // wild pointer error the pointer was either nonsense or came from
    // another heap.
    replacement_alloc = asan_realloc(BaseAddress, Size, &stack);
    CHECK((all_flags & HEAP_ZERO_MEMORY) == 0 &&
          "We cannot zero the memory as we do not know the previous size of "
          "the memory. This error should only occur if ASAN errors are "
          "non-fatal.");

    if (replacement_alloc) {
      AsanHeapMemoryNode *mem_node = new AsanHeapMemoryNode(replacement_alloc);
      AsanHeapMemoryNode *prev_tail = asan_heap->asan_memory.back();
      asan_heap->asan_memory.push_back(mem_node);

      {
        AsanMemoryMap::Handle h(&(asan_heap->memory_map),
                                reinterpret_cast<uptr>(replacement_alloc),
                                false, true);
        *h = prev_tail;
      }
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
      old_size = asan_malloc_usable_size(BaseAddress, pc, bp);
    }

    AsanHeapMemoryNode *found;
    {
      AsanMemoryMap::Handle h_delete(&(asan_heap->memory_map),
                                     reinterpret_cast<uptr>(BaseAddress), true,
                                     false);

      if (!h_delete.exists()) {
        return nullptr;
      }

      found = *h_delete;
    }

    replacement_alloc = asan_realloc(BaseAddress, Size, &stack);
    if (replacement_alloc == nullptr) {
      return nullptr;
    }

    if (all_flags & HEAP_ZERO_MEMORY) {
      size_t new_size = asan_malloc_usable_size(replacement_alloc, pc, bp);
      if (old_size < new_size) {
        REAL(memset)
        (((u8 *)replacement_alloc) + old_size, 0, new_size - old_size);
      }
    }

    // We need to remove the old pointer from both the heap list and the heap
    // map and then add the new pointer.
    if (replacement_alloc != BaseAddress) {
      if (found) {
        found->next->memory = replacement_alloc;
      } else {
        asan_heap->asan_memory.front()->memory = replacement_alloc;
      }

      AsanMemoryMap::Handle h_new(&(asan_heap->memory_map),
                                  reinterpret_cast<uptr>(replacement_alloc),
                                  false, true);
      *h_new = found;
    }
  } else if (UNLIKELY(!asan_unsupported_flags &&
                      owner == AllocationOwnership::RTL)) {
    old_size = REAL(RtlSizeHeap)(HeapHandle, Flags, BaseAddress);

    if (old_size != ~size_t{0}) {
      replacement_alloc = WRAP(RtlAllocateHeap)(HeapHandle, Flags, Size);
      if (replacement_alloc == nullptr) {
        return nullptr;
      } else {
        REAL(memcpy)
        (replacement_alloc, BaseAddress, Min<size_t>(Size, old_size));
        REAL(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
      }
    } else {
      return nullptr;
    }
  } else if (UNLIKELY(asan_unsupported_flags &&
                      owner == AllocationOwnership::ASAN)) {
    // Conversion to unsupported flags allocation,
    // transfer this allocation to the original allocator.
    replacement_alloc = REAL(RtlAllocateHeap)(HeapHandle, Flags, Size);

    if (replacement_alloc) {
      old_size = asan_malloc_usable_size(BaseAddress, pc, bp);
      REAL(memcpy)(replacement_alloc, BaseAddress, Min<size_t>(Size, old_size));
      WRAP(RtlFreeHeap)(HeapHandle, Flags, BaseAddress);
    }
  } else if (UNLIKELY(asan_unsupported_flags &&
                      owner == AllocationOwnership::RTL)) {
    // Currently owned by rtl using unsupported ASAN flags,
    // just pass back to original allocator.
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

enum class LockAction { Decrement = 0, Increment = 1 };
// forward declaring a few items for the shared versions of some of these
// Global/Local interceptors.
using GlobalLocalAlloc = HANDLE(WINAPI *)(UINT, SIZE_T);
using GlobalLocalRealloc = HANDLE(WINAPI *)(HANDLE, SIZE_T, UINT);
using GlobalLocalSize = SIZE_T(WINAPI *)(HANDLE);
using GlobalLocalFree = HANDLE(WINAPI *)(HANDLE);
using GlobalLocalLock = LPVOID(WINAPI *)(HANDLE);
using GlobalLocalUnlock = LPVOID(WINAPI *)(HANDLE);
HANDLE GlobalLocalGenericFree(GlobalLocalUnlock lockFunction,
                              GlobalLocalFree freeFunction, HANDLE hMem);
}  // namespace __asan

HANDLE SharedLockUnlock(HANDLE hMem, GlobalLocalLock lockFunc,
                        LockAction action) {
  CHECK(lockFunc != nullptr);
  if (asan_inited && !OWNED_BY_RTL(GetProcessHeap(), hMem)) {
    if (action == LockAction::Increment)
      return MoveableMemoryManager::GetInstance()->IncrementLockCount(hMem);
    else
      return MoveableMemoryManager::GetInstance()->DecrementLockCount(hMem);
  }
  // OWNED_BY_RTL was true or asan is not inited yet:
  return lockFunc(hMem);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalAlloc, UINT uFlags, SIZE_T dwBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & GLOBAL_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(GlobalAlloc)(uFlags, dwBytes);
  }

  return MoveableMemoryManager::GetInstance()->Alloc(uFlags, dwBytes);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalLock, HGLOBAL hMem) {
  return SharedLockUnlock(hMem, REAL(GlobalLock), LockAction::Increment);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalFree, HGLOBAL hMem) {
  return GlobalLocalGenericFree(REAL(GlobalLock), REAL(GlobalFree), hMem);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalUnlock, HGLOBAL hMem) {
  return SharedLockUnlock(hMem, REAL(GlobalUnlock), LockAction::Decrement);
}
INTERCEPTOR_WINAPI(HLOCAL, LocalLock, HLOCAL hMem) {
  return SharedLockUnlock(hMem, REAL(LocalLock), LockAction::Increment);
}

INTERCEPTOR_WINAPI(HGLOBAL, GlobalHandle, HGLOBAL hMem) {
  if (!asan_inited) {
    return REAL(GlobalHandle)(hMem);
  }
  return MoveableMemoryManager::GetInstance()->ResolvePointerToHandle(hMem);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalHandle, HLOCAL hMem) {
  if (!asan_inited) {
    return REAL(GlobalHandle)(hMem);
  }
  return MoveableMemoryManager::GetInstance()->ResolvePointerToHandle(hMem);
}

INTERCEPTOR_WINAPI(HGLOBAL, LocalUnlock, HGLOBAL hMem) {
  return SharedLockUnlock(hMem, REAL(LocalUnlock), LockAction::Decrement);
}

INTERCEPTOR_WINAPI(SIZE_T, GlobalSize, HGLOBAL hMem) {
  // We need to check whether the ASAN allocator owns the pointer
  // we're about to use. Allocations might occur before interception
  // takes place, so if it is not owned by RTL heap, the we can
  // pass it to ASAN heap for inspection.
  if (!asan_inited || OWNED_BY_RTL(GetProcessHeap(), hMem))
    return REAL(GlobalSize)(hMem);

  return MoveableMemoryManager::GetInstance()->GetAllocationSize(hMem);
}

namespace __asan {

enum class AllocationOwnership {
  OWNED_BY_UNKNOWN,
  OWNED_BY_ASAN,
  OWNED_BY_RTL,
  OWNED_BY_GLOBAL_OR_LOCAL,
  OWNED_BY_GLOBAL_OR_LOCAL_HANDLE,
};

HANDLE GlobalLocalGenericFree(GlobalLocalUnlock lockFunction,
                              GlobalLocalFree freeFunction, HANDLE hMem) {
  // If the memory we are trying to free is not owned
  // by ASan heap, then fall back to the original GlobalFree.
  if (!MoveableMemoryManager::GetInstance()->IsOwned(hMem)) {
    HGLOBAL pointer = lockFunction(hMem);
    if (pointer != nullptr) {
      // This was either a handle, or it was a pointer to begin with.
      // Either way, we can HeapValidate now.
      if (HeapValidate(GetProcessHeap(), 0, pointer)) {
        return freeFunction(hMem);
      }
    }
  }
  // Now we're either
  // a) an asan-owned pointer or handle
  // b) an invalid pointer which asan needs to report on.

  return MoveableMemoryManager::GetInstance()->Free(hMem);
}

AllocationOwnership CheckGlobalLocalHeapOwnership(
    HANDLE hMem, GlobalLocalLock lockFunc, GlobalLocalUnlock unlockFunc) {
  /*  To figure the validity of hMem, we use GlobalLock/LocalLock. Those two
   * functions can return three things: (1) the pointer that's passed in, in
   * which case it is a pointer owned by the Global/Local heap (2) the pointer
   * to the allocated object if it's a Global/Local heap HANDLE (3) nullptr if
   * it's a pointer which does not belong to the Global/Local heap Using these
   * three return types, we figure out if the pointer is TYPE_VALID_PTR or
   * TYPE_HANDLE or TYPE_UNKNOWN_PTR
   *
   * NOTE: As an implementation detail, movable memory objects also live on the
   * heap. HeapValidate will return true if given a moveable memory handle.
   *
   */

  // Check whether this pointer belongs to the memory manager first.
  if (MoveableMemoryManager::GetInstance()->IsOwned(hMem)) {
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
                         GlobalLocalUnlock unlockFunc, HeapCaller caller,
                         HANDLE hMem, DWORD dwBytes, UINT uFlags) {
  CHECK(reallocFunc && sizeFunc && freeFunc && allocFunc);
  GET_STACK_TRACE_MALLOC;
  AllocationOwnership ownershipState =
      CheckGlobalLocalHeapOwnership(hMem, lockFunc, unlockFunc);

  // If ASAN is not initialized then this needs to be default passed to the
  // original allocator. If the allocation is owned by the RTL then just
  // keep it there, since it's a leftover from before asan_init was called.
  if (UNLIKELY(!asan_inited) ||
      ((ownershipState ==
        AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL_HANDLE) &&
       (ownershipState == AllocationOwnership::OWNED_BY_GLOBAL_OR_LOCAL))) {
    return reallocFunc(hMem, dwBytes, uFlags);
  }
  // If the pointer is nonsense pass it directly to asan to report on it.
  if (ownershipState == AllocationOwnership::OWNED_BY_UNKNOWN)
    return asan_realloc(hMem, dwBytes, &stack);

  if (ownershipState == AllocationOwnership::OWNED_BY_ASAN) {
    CHECK((COMBINED_GLOBALLOCAL_UNSUPPORTED_FLAGS & uFlags) == 0);
    return MoveableMemoryManager::GetInstance()->ReAllocate(hMem, uFlags,
                                                            dwBytes, caller);
  }
  return nullptr;
}
}  // namespace __asan

INTERCEPTOR_WINAPI(HGLOBAL, GlobalReAlloc, HGLOBAL hMem, DWORD dwBytes,
                   UINT uFlags) {
  return ReAllocGlobalLocal(
      (GlobalLocalRealloc)REAL(GlobalReAlloc),
      (GlobalLocalSize)REAL(GlobalSize), (GlobalLocalFree)REAL(GlobalFree),
      (GlobalLocalAlloc)REAL(GlobalAlloc), (GlobalLocalLock)REAL(GlobalLock),
      (GlobalLocalUnlock)GlobalUnlock, HeapCaller::GLOBAL, (HANDLE)hMem,
      dwBytes, uFlags);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalAlloc, UINT uFlags, SIZE_T uBytes) {
  // If we encounter an unsupported flag, then we fall
  // back to the original allocator.
  if (uFlags & LOCAL_ALLOC_UNSUPPORTED_FLAGS) {
    return REAL(LocalAlloc)(uFlags, uBytes);
  }

  return MoveableMemoryManager::GetInstance()->Alloc(uFlags, uBytes);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalFree, HGLOBAL hMem) {
  // If the memory we are trying to free is not owned
  // ASan heap, then fall back to the original LocalFree.
  return GlobalLocalGenericFree(REAL(LocalLock), REAL(LocalFree), hMem);
}

INTERCEPTOR_WINAPI(SIZE_T, LocalSize, HGLOBAL hMem) {
  /* We need to check whether the ASAN allocator owns the pointer we're about to
   * use. Allocations might occur before interception takes place, so if it is
   * not owned by RTL heap, the we can pass it to ASAN heap for inspection.*/
  if (!asan_inited || OWNED_BY_RTL(GetProcessHeap(), hMem)) {
    return REAL(LocalSize)(hMem);
  }
  return MoveableMemoryManager::GetInstance()->GetAllocationSize(hMem);
}

INTERCEPTOR_WINAPI(HLOCAL, LocalReAlloc, HGLOBAL hMem, DWORD dwBytes,
                   UINT uFlags) {
  return ReAllocGlobalLocal(
      (GlobalLocalRealloc)REAL(LocalReAlloc), (GlobalLocalSize)REAL(LocalSize),
      (GlobalLocalFree)REAL(LocalFree), (GlobalLocalAlloc)REAL(LocalAlloc),
      (GlobalLocalLock)REAL(LocalLock), (GlobalLocalUnlock)LocalUnlock,
      HeapCaller::LOCAL, (HANDLE)hMem, dwBytes, uFlags);
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
  TryToOverrideFunction("_msize_dbg", (uptr)_msize_dbg);
#endif
  INTERCEPT_FUNCTION(GlobalAlloc);
  INTERCEPT_FUNCTION(GlobalFree);
  INTERCEPT_FUNCTION(GlobalSize);
  INTERCEPT_FUNCTION(GlobalReAlloc);
  INTERCEPT_FUNCTION(GlobalLock);
  INTERCEPT_FUNCTION(GlobalUnlock);
  INTERCEPT_FUNCTION(GlobalHandle);

  INTERCEPT_FUNCTION(LocalAlloc);
  INTERCEPT_FUNCTION(LocalFree);
  INTERCEPT_FUNCTION(LocalSize);
  INTERCEPT_FUNCTION(LocalReAlloc);
  INTERCEPT_FUNCTION(LocalLock);
  INTERCEPT_FUNCTION(LocalUnlock);
  INTERCEPT_FUNCTION(LocalHandle);

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
  __interception::OverrideFunction("RtlDestroyHeap", (uptr)WRAP(RtlDestroyHeap),
                                   (uptr *)&REAL(RtlDestroyHeap));
#endif  // defined(ASAN_DYNAMIC)
}
}  // namespace __asan

#endif  // _WIN32
