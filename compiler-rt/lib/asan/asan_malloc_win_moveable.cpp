//===-- asan_malloc_win_moveable.cpp --------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Movable heap allocation manager for Global/Local Alloc interception.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_WINDOWS
#include "asan_allocator.h"
#include "asan_errors.h"
#include "asan_internal.h"
#include "asan_malloc_win_moveable.h"
#include "asan_report.h"
#include "asan_stack.h"
#include "asan_win_immortalize.h"
#include "asan_win_scoped_lock.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_list.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_vector.h"

#pragma warning(push)
#pragma warning(disable : 4273)
extern "C" __declspec(restrict) void *_recalloc(void *, size_t, size_t);
#pragma warning(pop)

extern "C" __declspec(dllimport) void WINAPI SetLastError(DWORD dwErrCode);

namespace __asan_win_moveable {
using namespace __asan;
using namespace __sanitizer;

struct FixedAllocationEntry {
  FixedAllocationEntry *next;
  void *addr;

  explicit FixedAllocationEntry(void *_addr) noexcept
      : next(nullptr), addr(_addr) {}

  static void *operator new(size_t size) { return InternalAlloc(size); }
  static void operator delete(void *p) { InternalFree(p); }
};

struct MoveableAllocationEntry {
  void *handle;
  void *addr;
  size_t lock_count;  // lock count for this movable section.

  explicit MoveableAllocationEntry(size_t handle_index,
                                   void *_addr = nullptr) noexcept
      : handle(reinterpret_cast<void *>(handle_index)),
        addr(_addr),
        lock_count(0) {}

  static void *operator new(size_t size) { return InternalAlloc(size); }
  static void operator delete(void *p) { InternalFree(p); }
};

struct AllocationEntry {
  void *metadata;
  void *addr;
};

using HandleMap = AddrHashMap<AllocationEntry *, 11>;
using Handle = HandleMap::Handle;

/* Background:
  These vintage allocators provided a primitive DIY interface for paging. We're
  mocking this behavior to catch bugs in legacy code which makes use of this
  feature.

  Since we cannot include Windows.h or any stdlib items in asan_malloc_win
  itself, these items are split into their own obj.

  Some design notes on ensuring no overlap of pointers and handles and getting
  O(1) performance on handle->pointer resolution:

  There is an arbitrary limit of 0xFFFF on the number of handles the
  Global/Local heap can have (hardcoded, not even a #define, in the code).

  HANDLE is a void* but the handle value itself only needs to take up the lower
  order word, so the masks for the tags and handles would be ~0xFFFF and 0xFFFF.

  So now returning and receiving a handle involves a bitwise OR/AND to
  add/remove the tag. If the the index of a handle in our handle table (call it
  ‘the_index’)would be 1, we now return (HANDLE_TAG | the_index). Resolving the
  handle to table index involves handle & 0xFFFF to get the index and handle &
  ~0xFFFF to get the tag value. */

struct MemoryManagerResources {
  MemoryManagerResources() noexcept { fixed_entries.clear(); }

  IntrusiveList<FixedAllocationEntry> fixed_entries;
  Vector<MoveableAllocationEntry *> handle_reuse_list;
  Vector<MoveableAllocationEntry *> moveable_entries;

  /* To resolve pointer->handle_entry quickly, create a map to track pointer to
   * handle_entry associations. */
  HandleMap pointer_to_handle_map;

  // lock elements which will be passed into the shared RAII lock
  SpinMutex lock = {};
  atomic_uint32_t thread_id = {};

  static void *operator new(size_t, void *p) noexcept { return p; }
};

// Create an immortal memory resources class singleton.
MemoryManagerResources &GetResourcesInstance() {
  return immortalize<MemoryManagerResources>();
}

constexpr uptr global_local_heap_handle_limit = 0xFFFF;
constexpr uptr moveable_handle_tag = ~global_local_heap_handle_limit;

void *TagHandleIndex(uptr index) {
  return reinterpret_cast<void *>(moveable_handle_tag | index);
}

uptr ResolveHandleToIndex(void *handle) {
  return reinterpret_cast<uptr>(handle) & ~moveable_handle_tag;
}

MoveableAllocationEntry *ResolveHandleToTableEntry(void *handle) {
  uptr index = ResolveHandleToIndex(handle);

  auto &resource_instance = GetResourcesInstance();
  auto &moveable_entries = resource_instance.moveable_entries;

  RecursiveScopedLock scoped_lock(resource_instance.lock,
                                  resource_instance.thread_id);

  if (index >= moveable_entries.Size() || moveable_entries[index] == nullptr) {
    SetLastError(ERROR_INVALID_HANDLE);
    return nullptr;
  }

  return moveable_entries[index];
}

bool IsOwnedPointer(void *addr) {
  auto &resource_instance = GetResourcesInstance();
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  // This lock might not be necessary as the hash map is atomic.
  RecursiveScopedLock scoped_lock(resource_instance.lock,
                                  resource_instance.thread_id);

  Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(addr), false, false);
  return h.exists();
}

void *ResolveHandleToPointer(void *item) {
  MoveableAllocationEntry *table_entry = ResolveHandleToTableEntry(item);
  if (table_entry != nullptr) {
    return table_entry->addr;
  }

  if (IsOwnedPointer(item)) {
    SetLastError(NO_ERROR);
    return item;
  }

  return nullptr;
}

bool IsOwned(void *item) { return ResolveHandleToPointer(item) != nullptr; }

void *ResolvePointerToHandle(void *addr) {
  auto &resource_instance = GetResourcesInstance();
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  RecursiveScopedLock scoped_lock(resource_instance.lock,
                                  resource_instance.thread_id);

  Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(addr), false, false);
  if (!h.exists()) {
    return nullptr;
  }

  return *h;
}

bool IsValidMoveableHandle(void *handle) {
  return (reinterpret_cast<uptr>(handle) & ~global_local_heap_handle_limit) ==
         moveable_handle_tag;
}

bool IsValidItem(void *item) {
  return IsValidMoveableHandle(item) || IsOwnedPointer(item);
}

// helper function to optionally zero an allocation.
void *AllocMaybeZero(size_t size, bool zero_init, BufferedStackTrace &stack) {
  if (zero_init) {
    return asan_calloc(size, 1, &stack);
  } else {
    return asan_malloc(size, &stack);
  }
}

#define HANDLE_OUT_OF_MEMORY(x)        \
  do                                   \
    if (!x) {                          \
      SetLastError(ERROR_OUTOFMEMORY); \
      return nullptr;                  \
    }                                  \
  while (0)

MoveableAllocationEntry *AddMoveableAllocationInternal(
    size_t size, bool zero_init, BufferedStackTrace &stack) {
  void *new_region = AllocMaybeZero(size, zero_init, stack);
  HANDLE_OUT_OF_MEMORY(new_region);

  auto &resource_instance = GetResourcesInstance();
  auto &handle_reuse_list = resource_instance.handle_reuse_list;
  auto &moveable_entries = resource_instance.moveable_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  MoveableAllocationEntry *handle_entry = nullptr;
  {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);

    uptr free_handles = handle_reuse_list.Size();
    if (free_handles != 0) {
      handle_entry = handle_reuse_list[free_handles - 1];
      handle_reuse_list.PopBack();

      handle_entry->addr = new_region;
      handle_entry->lock_count = 0;
      moveable_entries[reinterpret_cast<uptr>(handle_entry->handle)] =
          handle_entry;
    } else if (free_handles <= global_local_heap_handle_limit) {
      handle_entry =
          new MoveableAllocationEntry(moveable_entries.Size(), new_region);
    }

    if (handle_entry != nullptr) {
      moveable_entries.PushBack(handle_entry);

      {
        Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(new_region),
                 false, true);
        DCHECK(h.created());
        *h = reinterpret_cast<AllocationEntry *>(handle_entry);
      }
    }
  }

  if (handle_entry == nullptr) {
    asan_free(new_region, &stack, FROM_MALLOC);
    SetLastError(ERROR_OUTOFMEMORY);
    return nullptr;
  }

  return handle_entry;
}

void *AddMoveableAllocation(size_t size, bool zero_init,
                            BufferedStackTrace &stack) {
  MoveableAllocationEntry *entry =
      AddMoveableAllocationInternal(size, zero_init, stack);

  if (entry == nullptr) {
    return nullptr;
  }

  return TagHandleIndex(reinterpret_cast<uptr>(entry->handle));
}

void *AddFixedAllocation(size_t size, bool zero_init,
                         BufferedStackTrace &stack) {
  void *new_region = AllocMaybeZero(size, zero_init, stack);
  HANDLE_OUT_OF_MEMORY(new_region);

  auto &resource_instance = GetResourcesInstance();
  auto &fixed_entries = resource_instance.fixed_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  FixedAllocationEntry *handle_entry = new FixedAllocationEntry(new_region);

  if (handle_entry == nullptr) {
    asan_free(new_region, &stack, FROM_MALLOC);
    SetLastError(ERROR_OUTOFMEMORY);
    return nullptr;
  }

  RecursiveScopedLock scoped_lock(resource_instance.lock,
                                  resource_instance.thread_id);
  {
    Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(new_region), false,
             true);
    DCHECK(h.created());
    *h = reinterpret_cast<AllocationEntry *>(fixed_entries.back());
  }
  fixed_entries.push_back(handle_entry);

  return new_region;
}

void *ReallocFixedToHandleInternal(void *original, bool zero_init,
                                   BufferedStackTrace &stack) {
  DCHECK(IsOwnedPointer(original));

  size_t original_size = asan_malloc_usable_size(
      original, stack.trace_buffer[0], stack.top_frame_bp);
  MoveableAllocationEntry *new_handle =
      AddMoveableAllocationInternal(original_size, zero_init, stack);

  if (new_handle) {
    void *new_ptr = new_handle->addr;
    REAL(memcpy)(new_ptr, original, original_size);
    return TagHandleIndex(reinterpret_cast<uptr>(new_handle->handle));
  }

  return nullptr;
}

void *FreeMoveableInternal(void *handle, BufferedStackTrace &stack) {
  auto &resource_instance = GetResourcesInstance();
  auto &handle_reuse_list = resource_instance.handle_reuse_list;
  auto &moveable_entries = resource_instance.moveable_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  void *backing_memory;
  uptr entry_index;
  uptr moveable_entries_size;
  MoveableAllocationEntry *entry;
  {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);

    entry = ResolveHandleToTableEntry(handle);

    if (entry != nullptr) {
      moveable_entries_size = moveable_entries.Size();
      entry_index = reinterpret_cast<uptr>(entry->handle);
      backing_memory = entry->addr;

      {
        Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(backing_memory),
                 true, false);
        DCHECK(h.exists());
      }

      moveable_entries[reinterpret_cast<uptr>(entry->handle)] = nullptr;
      handle_reuse_list.PushBack(entry);
    }
  }

  if (entry == nullptr) {
    if (entry_index < moveable_entries_size) {
      // TODO: Make a fully fleshed error type for double free of handle
      ReportDoubleFree(reinterpret_cast<uptr>(handle), &stack);
    } else {
      // TODO: Make a fully fleshed error on free not created for handle
      ReportFreeNotMalloced(reinterpret_cast<uptr>(handle), &stack);
    }

    return handle;
  }

  asan_free(backing_memory, &stack, FROM_MALLOC);
  return nullptr;
}

void *FreeFixedInternal(void *addr, BufferedStackTrace &stack) {
  auto &resource_instance = GetResourcesInstance();
  auto &fixed_entries = resource_instance.fixed_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  bool found;
  {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);
    FixedAllocationEntry *prev_entry;
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(addr), true,
               false);
      found = h.exists();

      if (found) {
        prev_entry = reinterpret_cast<FixedAllocationEntry *>(*h);
      }
    }

    if (found) {
    }

    if (prev_entry == nullptr) {
      InternalFree(fixed_entries.front());
      fixed_entries.pop_front();
    } else {
      FixedAllocationEntry *curr = prev_entry->next;
      DCHECK(curr->addr == addr);
      fixed_entries.extract(prev_entry, curr);
      InternalFree(curr);

      if (prev_entry->next != nullptr) {
        Handle h(&pointer_to_handle_map,
                 reinterpret_cast<uptr>(prev_entry->next->addr), false, false);
        DCHECK(h.exists());
        *h = reinterpret_cast<AllocationEntry *>(prev_entry);
      }
    }
  }

  void *ret_addr = nullptr;
  if (!found) {
    SetLastError(ERROR_INVALID_HANDLE);
    ret_addr = addr;
  }

  asan_free(addr, &stack, FROM_MALLOC);
  return ret_addr;
}

void *Free(void *item, BufferedStackTrace &stack) {
  if (IsValidMoveableHandle(item)) {
    return FreeMoveableInternal(item, stack);
  }

  return FreeFixedInternal(item, stack);
}

void *IncrementLockCount(void *item, uptr pc, uptr bp, uptr sp) {
  {
    RecursiveScopedLock scoped_lock(GetResourcesInstance().lock,
                                    GetResourcesInstance().thread_id);
    if (IsValidMoveableHandle(item)) {
      MoveableAllocationEntry *entry = ResolveHandleToTableEntry(item);
      if (entry != nullptr) {
        if (entry->lock_count++ == GMEM_LOCKCOUNT) {
          entry->lock_count--;
        }

        return entry->addr;
      }
    } else if (IsOwnedPointer(item)) {
      return item;
    }
  }

  // TODO: Make a fully fleshed error type
  ReportGenericError(pc, bp, sp, reinterpret_cast<uptr>(item), true,
                     sizeof(void *), 0, false);
  return nullptr;
}

size_t GetAllocationSize(void *item, BufferedStackTrace &stack) {
  void *ptr = nullptr;

  {
    RecursiveScopedLock scoped_lock(GetResourcesInstance().lock,
                                    GetResourcesInstance().thread_id);

    if (IsValidMoveableHandle(item)) {
      ptr = ResolveHandleToPointer(item);
    } else if (IsOwnedPointer(item)) {
      ptr = item;
    }
  }

  if (ptr == nullptr) {
    ReportMallocUsableSizeNotOwned(reinterpret_cast<uptr>(item), &stack);
    return 0;
  }

  return asan_malloc_usable_size(ptr, stack.trace_buffer[0],
                                 stack.top_frame_bp);
}

void *ReallocFixedToFixedInternal(void *original, size_t new_size,
                                  bool zero_init, BufferedStackTrace &stack) {
  DCHECK(IsOwnedPointer(original) || original == nullptr);

  auto &resource_instance = GetResourcesInstance();
  auto &fixed_entries = resource_instance.fixed_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  void *addr;
  if (zero_init) {
    addr = _recalloc(original, new_size, 1);
  } else {
    addr = asan_realloc(original, new_size, &stack);
  }

  if (addr == nullptr) {
    return nullptr;
  }

  {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);

    FixedAllocationEntry *prev_entry;
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(original), true,
               false);
      DCHECK(h.exists());
      prev_entry = reinterpret_cast<FixedAllocationEntry *>(*h);
    }
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(addr), false,
               true);
      DCHECK(h.created());
      *h = reinterpret_cast<AllocationEntry *>(prev_entry);
    }

    if (prev_entry == nullptr) {
      fixed_entries.front()->addr = addr;
    } else {
      prev_entry->next->addr = addr;
    }
  }

  return addr;
}

void *ReallocHandleToHandleInternal(void *original, size_t new_size,
                                    bool zero_init, BufferedStackTrace &stack,
                                    uptr sp) {
  DCHECK(original != nullptr && IsValidMoveableHandle(original));

  auto &resource_instance = GetResourcesInstance();
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  void *addr;
  MoveableAllocationEntry *handle_entry;
  {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);

    handle_entry = ResolveHandleToTableEntry(original);
    if (!handle_entry) {
      // TODO: Make a fully fleshed error type for realloc on invalid handle
      ReportGenericError(stack.trace_buffer[0], stack.top_frame_bp, sp,
                         reinterpret_cast<uptr>(original), false,
                         sizeof(void *), 0, false);
      return nullptr;
    }

    addr = handle_entry->addr;
  }

  // TODO: We release the scoped_lock to avoid a potential deadlock when
  // calling _recalloc/realloc but in doing so we introduce a potential
  // race condition where the handle might be deleted under us.
  void *new_addr;
  size_t original_size;
  if (zero_init) {
    original_size = asan_malloc_usable_size(addr, stack.trace_buffer[0],
                                            stack.top_frame_bp);
  }

  new_addr = asan_realloc(addr, new_size, &stack);
  if (new_addr == nullptr) {
    return nullptr;
  }

  if (zero_init) {
    size_t new_size = asan_malloc_usable_size(new_addr, stack.trace_buffer[0],
                                              stack.top_frame_bp);
    if (original_size < new_size) {
      REAL(memset)
      (static_cast<char *>(new_addr) + original_size, 0,
       new_size - original_size);
    }
  }

  if (new_addr != addr) {
    RecursiveScopedLock scoped_lock(resource_instance.lock,
                                    resource_instance.thread_id);
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(addr), true,
               false);
      DCHECK(h.exists());
    }
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(new_addr), false,
               true);
      DCHECK(h.created());
      *h = reinterpret_cast<AllocationEntry *>(handle_entry);
    }
    handle_entry->addr = new_addr;
  }

  return original;
}

void *ReAllocate(void *item, size_t flags, size_t size, HeapCaller caller,
                 BufferedStackTrace &stack, uptr sp) {
  if (!__asan::flags()->allocator_frees_and_returns_null_on_realloc_zero) {
    Report(
        "WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to "
        "FALSE."
        " This is not consistent with libcmt/ucrt/msvcrt behavior.");
  }

  if (flags & MODIFY) {
    if ((flags & MOVEABLE) && caller == HeapCaller::GLOBAL &&
        IsOwnedPointer(item)) {
      return ReallocFixedToHandleInternal(item, flags & ZEROINIT, stack);
    }

    return item;
  } else {
    if (IsValidMoveableHandle(item)) {
      if (size == 0) {
        // TODO: We might need to check the lock count here before freeing
        FreeMoveableInternal(item, stack);

        // Returning nullptr of ReAlloc of size zero emulates the behavior of
        // the release heap. The debug heap will only return nullptr on an
        // invalid handle or other error.
        return nullptr;
      } else {
        return ReallocHandleToHandleInternal(item, size, flags & ZEROINIT,
                                             stack, sp);
      }
    } else {
      return ReallocFixedToFixedInternal(item, size, flags & ZEROINIT, stack);
    }
  }
}

bool DecrementLockCount(void *item, uptr pc, uptr bp, uptr sp) {
  {
    RecursiveScopedLock scoped_lock(GetResourcesInstance().lock,
                                    GetResourcesInstance().thread_id);
    if (IsValidMoveableHandle(item)) {
      MoveableAllocationEntry *entry = ResolveHandleToTableEntry(item);
      if (entry != nullptr) {
        if (entry->lock_count > 1) {
          entry->lock_count--;
          return true;
        } else if (entry->lock_count == 1) {
          entry->lock_count--;
          SetLastError(NO_ERROR);
          return false;
        } else if (entry->lock_count == 0) {
          SetLastError(ERROR_NOT_LOCKED);
          return false;
        }
      }
    } else if (IsOwnedPointer(item)) {
      return false;
    }
  }

  // TODO: Make a fully fleshed error type
  ReportGenericError(pc, bp, sp, reinterpret_cast<uptr>(item), true,
                     sizeof(void *), 0, false);
  return false;
}

size_t GetLockCount(void *item, uptr pc, uptr bp, uptr sp) {
  {
    RecursiveScopedLock scoped_lock(GetResourcesInstance().lock,
                                    GetResourcesInstance().thread_id);
    if (IsValidMoveableHandle(item)) {
      MoveableAllocationEntry *entry = ResolveHandleToTableEntry(item);
      if (entry == nullptr) {
        // TODO: Make a fully fleshed error type
        ReportGenericError(pc, bp, sp, reinterpret_cast<uptr>(item), true,
                           sizeof(void *), 0, false);
        return ~size_t{0};
      }

      return entry->lock_count;
    } else if (IsOwnedPointer(item)) {
      return 0;
    }
  }

  // TODO: Make a fully fleshed error type
  ReportGenericError(pc, bp, sp, reinterpret_cast<uptr>(item), true,
                     sizeof(void *), 0, false);
  return ~size_t{0};
}

void *Alloc(unsigned long flags, size_t size, BufferedStackTrace &stack) {
  bool zero_alloc = flags & ZEROINIT;
  if (flags & MOVEABLE) {
    return AddMoveableAllocation(size, zero_alloc, stack);
  }

  return AddFixedAllocation(size, zero_alloc, stack);
}

void Purge() {
  auto &resource_instance = GetResourcesInstance();
  auto &fixed_entries = resource_instance.fixed_entries;
  auto &handle_reuse_list = resource_instance.handle_reuse_list;
  auto &moveable_entries = resource_instance.moveable_entries;
  auto &pointer_to_handle_map = resource_instance.pointer_to_handle_map;

  RecursiveScopedLock scoped_lock(resource_instance.lock,
                                  resource_instance.thread_id);

  FixedAllocationEntry *curr = fixed_entries.front();
  FixedAllocationEntry *next;
  while (curr != nullptr) {
    next = curr->next;
    {
      Handle h(&pointer_to_handle_map, reinterpret_cast<uptr>(curr->addr), true,
               false);
      DCHECK(h.exists());
    }
    InternalFree(curr);
    curr = next;
  }
  fixed_entries.clear();

  for (uptr i = 0; i < handle_reuse_list.Size(); ++i) {
    {
      Handle h(&pointer_to_handle_map,
               reinterpret_cast<uptr>(handle_reuse_list[i]->addr), true, false);
      DCHECK(h.exists());
    }
    InternalFree(handle_reuse_list[i]);
  }
  handle_reuse_list.Reset();

  for (uptr i = 0; i < moveable_entries.Size(); ++i) {
    if (moveable_entries[i] != nullptr) {
      {
        Handle h(&pointer_to_handle_map,
                 reinterpret_cast<uptr>(moveable_entries[i]->addr), true,
                 false);
        DCHECK(h.exists());
      }
      InternalFree(moveable_entries[i]);
    }
  }
  moveable_entries.Reset();
}
}  // namespace __asan_win_moveable

#endif  // SANITIZER_WINDOWS
