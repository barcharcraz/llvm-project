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

#include <Windows.h>
#include <cassert>
#include <errhandlingapi.h>
#include <mutex>
#include <queue>
#include <stdio.h>
#include <unordered_map>
#include <vector>
#include "sanitizer_common\sanitizer_internal_defs.h"
#include "asan_malloc_win_moveable.h"

/* Background:
  These vintage allocators provided a primitive DIY interface for paging. We're
  mocking this behavior to catch bugs in legacy code which makes use of this
  feature.

  Since we cannot include Windows.h or any stdlib items in asan_malloc_win
  itself, these items are split into their own obj.

  Some design notes on ensuring no overlap of pointers and handles and getting
  O(1) performance on handle->pointer resolution:

  There is an arbitrary limit of 0xFFFF on the number of handles the
  Global/Local heap can have (hardcoded, not even a #define, in the code). That
  limit means we can just reserve 0xFFFF of memory to serve as our handle
  values. Reserving that memory ensures no overlap between handle values and
  pointers, plus it makes handle validation quick since we can now use the
  higher order bytes of the handle region to tag our handles.

  HANDLE is a void* but the handle value itself only needs to take up the lower
  order word, so the masks for the tags and handles would be ~0xFFFF and 0xFFFF.

  So now returning and receiving a handle involves a bitwise OR/AND to
  add/remove the tag. If the the index of a handle in our handle table (call it
  ‘the_index’)would be 1, we now return (HANDLE_TAG | the_index). Resolving the
  handle to table index involves handle & 0xFFFF to get the index and handle &
  ~0xFFFF to get the tag value. */
static std::vector<MoveableAllocEntry *> MoveableEntries;
static std::queue<MoveableAllocEntry *> HandleReuseList;

/* This const will be both our handle limit and a mask to remove the handle
 * tag*/
constexpr size_t GlobalLocalHeapHandleLimit = 0xFFFF;

/* Make this reservation static, but to ensure it's aligned apply the
 * aligned_malloc technique of reserving twice the amount of space and using the
 * first aligned address within that reservation as element 0. */
static char AlignedHandleReservation[GlobalLocalHeapHandleLimit * 2];
static void *MoveableHandleTag; // <-- will be set to the first aligned address.

/* To resolve pointer->handle_entry quickly, create a map to track pointer to
 * handle_entry associations. */
static std::unordered_map<void *, MoveableAllocEntry *> PointerToHandleMap;

/* The ReAlloc case for this needs to call Free, which also grabs this mutex
 * below. This might need a redesign, (add an optional bool to skip the lock in
 * some cases?) but for now I'm just using a recursive lock. */
static std::recursive_mutex GlobalHeapMutex;

// ignore dll linkage warning: we are defining our own versions in
// asan_malloc_win.
#pragma warning(push)
#pragma warning(disable: 4273)

/* Link against extern symbols to call the intercepted vesions without
 * needing to deal with the internal asan interface. */
_declspec(restrict) void *malloc(size_t);
_declspec(restrict) void *calloc(size_t, size_t);
void free(void *);
_declspec(restrict) void *realloc(void *, size_t);
_declspec(restrict) void *_recalloc(void *, size_t, size_t);
size_t _msize(void *);
_declspec(dllimport) void WINAPI SetLastError(DWORD dwErrCode);

#pragma warning(pop)

MoveableMemoryManager::MoveableMemoryManager() {
  /* Get the first aligned item within this region which will be used as the
   * handle tag (and first handle value) */
  MoveableHandleTag =
      (void *)((reinterpret_cast<size_t>(&AlignedHandleReservation[0]) +
                GlobalLocalHeapHandleLimit) &
               ~GlobalLocalHeapHandleLimit);

  // static to make sure the LMEM/GMEM genericized flag values we are using
  // haven't somehow changed.
  static_assert(GMEM_FIXED == LMEM_FIXED && GMEM_FIXED == FIXED);
  static_assert(GMEM_ZEROINIT == LMEM_ZEROINIT && GMEM_ZEROINIT == ZEROINIT);
  static_assert(GMEM_MOVEABLE == LMEM_MOVEABLE && GMEM_MOVEABLE == MOVEABLE);
  static_assert(GMEM_MODIFY == LMEM_MODIFY && GMEM_MODIFY == MODIFY);
  static_assert(GMEM_NOCOMPACT == LMEM_NOCOMPACT &&
                GMEM_NOCOMPACT == NOCOMPACT);
  static_assert(GMEM_INVALID_HANDLE == LMEM_INVALID_HANDLE &&
                GMEM_INVALID_HANDLE == INVALID_HANDLE);
}

void *MoveableMemoryManager::GetHandleReservation() {
  return static_cast<void *>(AlignedHandleReservation);
}

size_t MoveableMemoryManager::GetHandleTag() {
  return reinterpret_cast<size_t>(MoveableHandleTag);
}

// helper function to optionally zero an allocation.
void *AllocMaybeZero(size_t size, bool zero_init) {
  if (zero_init)
    return calloc(size, 1);
  else
    return malloc(size);
}

#define HANDLE_OUT_OF_MEMORY(x)                                                \
  do                                                                           \
    if (!x) {                                                                  \
      SetLastError(ERROR_OUTOFMEMORY);                                         \
      return nullptr;                                                          \
    }                                                                          \
  while (0)

void *MoveableMemoryManager::TagHandleIndex(size_t index) {
  return (void *)(GetHandleTag() | index);
}

void *MoveableMemoryManager::AddMoveableAllocation(size_t size,
                                                   bool zero_init) {
  void *new_region = AllocMaybeZero(size, zero_init);
  HANDLE_OUT_OF_MEMORY(new_region);
  size_t next_available_handle = MoveableEntries.size();
  if (next_available_handle <= 0xFFFF) {
    MoveableAllocEntry *new_handle = new (std::nothrow)
        MoveableAllocEntry(next_available_handle, new_region);
    if (new_handle == nullptr) {
      free(new_region);
      SetLastError(ERROR_OUTOFMEMORY);
      return nullptr;
    }
    MoveableEntries.push_back(new_handle);
    PointerToHandleMap[new_region] = new_handle;
    return TagHandleIndex(next_available_handle);
  }
  MoveableAllocEntry *reuseEntry = HandleReuseList.front();
  HandleReuseList.pop();
  CHECK(reuseEntry != nullptr);
  // reuseEntry->handle value remains the same
  reuseEntry->freed = false;
  reuseEntry->addr = new_region;
  reuseEntry->lockCount = 0;
  return TagHandleIndex((size_t)(reuseEntry->handle));
}

void *MoveableMemoryManager::AddFixedAllocation(size_t size, bool zero_init) {
  void *new_region = AllocMaybeZero(size, zero_init);
  HANDLE_OUT_OF_MEMORY(new_region);
  PointerToHandleMap[new_region] = nullptr;
  return new_region;
}

size_t MoveableMemoryManager::ResolveHandleToIndex(void *handle) {
  /* Flipping the bits instead of subtraction still allows a quick check to see
   * if the handle is valid */
  return (((size_t)handle) & ~((size_t)MoveableHandleTag));
}

void *MoveableMemoryManager::ResolveHandleToPointer(void *ident) {
  MoveableAllocEntry *table_entry = ResolveHandleToTableEntry(ident);
  if (table_entry == nullptr) {
    SetLastError(ERROR_INVALID_HANDLE);
    return nullptr;
  }
  return table_entry->addr;
}

MoveableAllocEntry *
MoveableMemoryManager::ResolveHandleToTableEntry(void *handle) {
  size_t index = ResolveHandleToIndex(handle);
  if (index >= MoveableEntries.size()) {
    SetLastError(ERROR_INVALID_HANDLE);
    return nullptr;
  }
  return MoveableEntries.at(index);
}

// TODO: Resolve what needs to happen for these error cases.
//       Windows just crashes inconsistently on some of these.
//       A report would be nice...
void *MoveableMemoryManager::ResolvePointerToHandle(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);

  if (IsOwnedPointer(ident)) {
    MoveableAllocEntry *handle_entry = PointerToHandleMap.at(ident);
    if (handle_entry) {
      return handle_entry->handle;
    }
    return nullptr;
  }
  CHECK(0 && "Untracked pointer passed into "
              "MoveableMemoryManager::ResolvePointerToHandle");
  return nullptr;
}

// These might need a refactor but I'll wait until they're finished.
// TODO: overflows and underflows
void *MoveableMemoryManager::IncrementLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    if (!entry) {
      return nullptr;
    }
    entry->lockCount++; // <- could overflow
    return ResolveHandleToPointer(ident);
  } else if (IsOwnedPointer(ident)) {
    return ident; // for fixed memory the pointer is just returned (MSDN)
  } else {
    CHECK(0 && "Wild pointer passed into [Global|Local]Lock");
    // TODO: Is there a better way to handle this?
  }
  return nullptr;
}
/* GMEM_MODIFY allows you to convert between moveable and fixed allocations.
  The flag means that these functions ignore any size parameter passed into it.
*/

void *MoveableMemoryManager::ReallocFixedToHandle(void *original,
                                                  bool zero_init) {
  CHECK(IsOwnedPointer(original));
  size_t original_size = _msize(original);
  void *new_allocation = AddMoveableAllocation(original_size, zero_init);
  if (new_allocation) {
    void *new_ptr = ResolveHandleToPointer(new_allocation);
    memcpy(new_ptr, original, original_size);
    return new_allocation;
  }
  return nullptr;
}

size_t MoveableMemoryManager::GetAllocationSize(void *memory_ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  void *ptr;
  if (IsOwnedHandle(memory_ident)) {
    ptr = ResolveHandleToPointer(memory_ident);
  } else if (IsOwnedPointer(memory_ident)) {
    ptr = memory_ident;
  } else {
    CHECK(0 && "Memory ID passed to MoveableMemoryManager::GetAllocationSize "
                "is not valid!\n");
  }
  return _msize(ptr);
}
void *MoveableMemoryManager::ReallocFixedToFixed(void *original,
                                                 size_t new_size,
                                                 bool zero_init) {
  // If the pointer has been set to null we still want to give it to ASan to
  // report the use.
  CHECK(IsOwnedPointer(original) || original == nullptr);
  if (zero_init)
    return _recalloc(original, new_size, 1);
  else
    return realloc(original, new_size);
}

void *MoveableMemoryManager::ReallocHandleToHandle(void *original,
                                                   size_t new_size,
                                                   bool zero_init) {
  // If the handle is nullptr something is wrong on our end.
  CHECK(original != nullptr && IsOwnedHandle(original));
  // if the resolved ptr is free, if this item is null, we just pass it to the
  // interceptor no matter what to generate a report.
  void *ptr = ResolveHandleToPointer(original);
  return ReallocFixedToFixed(ptr, new_size, zero_init);
}

void *MoveableMemoryManager::DecrementLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    if (!entry) {
      return nullptr;
    }
    if (entry->lockCount > 1) {
      entry->lockCount--;
      return ResolveHandleToPointer(ident);
    } else if (entry->lockCount == 1) {
      entry->lockCount--;
      SetLastError(NO_ERROR);
      return nullptr;
    } else if (entry->lockCount == 0) {
      SetLastError(ERROR_NOT_LOCKED);
      return nullptr;
    }
  } else if (IsOwnedPointer(ident)) {
    return ident; // for fixed memory the pointer is just returned (MSDN)
  } else {
    CHECK(0 && "Wild pointer passed into [Global|Local]Unlock");
  }
  return nullptr;
}

size_t MoveableMemoryManager::GetLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    return entry->lockCount;
  } else if (IsOwnedPointer(ident)) {
    return 0; // lock count is always 0 for pointers according to MSDN.
  } else {
    CHECK(0 && "Wild pointer passed into [Global|Local]Flags");
  }
  return 0;
}

bool MoveableMemoryManager::IsOwnedHandle(void *item) {
  auto HandleTag = reinterpret_cast<size_t>(MoveableHandleTag);
  bool HandleTagIsCorrect = ((reinterpret_cast<size_t>(item) &
          ~(GlobalLocalHeapHandleLimit)) == HandleTag);
  bool HandleIsInRange = ((reinterpret_cast<size_t>(item) - HandleTag) <=
          GlobalLocalHeapHandleLimit);
  return HandleTagIsCorrect && HandleIsInRange;
}

bool MoveableMemoryManager::IsOwnedPointer(void *item) {
  return PointerToHandleMap.find(item) != PointerToHandleMap.end();
}

bool MoveableMemoryManager::IsOwned(void *item) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  return IsOwnedPointer(item) || IsOwnedHandle(item);
}

void *MoveableMemoryManager::ReAllocate(void *ident, size_t flags, size_t size,
                                        HeapCaller caller) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  if (flags & MODIFY) {
    if (IsOwnedPointer(ident)) {
      // conversion is one way, fixed to moveable only.
      // Only GlobalAlloc allows conversion from fixed to moveable.
      if ((flags & MOVEABLE) && caller == HeapCaller::GLOBAL) {
        return ReallocFixedToHandle(ident, flags & ZEROINIT);
      }
    }
    // There is no conversion to perform, return the original
    // handle/pointer.
    return ident;
  } else {
    // There is no attribute conversion to handle, so perform a regular
    // realloc.
    if (IsOwnedHandle(ident)) {
      if (size == 0) {
        return Free(ident);
      } else {
        return ReallocHandleToHandle(ident, size, flags & ZEROINIT);
      }
    } else {
      return ReallocFixedToFixed(ident, size, flags & ZEROINIT);
    }
  }
}

// TODO: Add an ASan report type for double free on a stale handle
void *MoveableMemoryManager::Free(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    void *backing_memory = ResolveHandleToPointer(ident);
    free(backing_memory);
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    CHECK(entry != nullptr);
    PointerToHandleMap[backing_memory] = nullptr;

    /* NOTE: Lock count is not affected by free
             you can even get the lock count of the handle after
             the base memory is freed.
    */
    entry->freed = true;
    HandleReuseList.push(entry);
    return nullptr;
  }
  /* If this is a bad free it will be reported on. */
  free(ident);
  return nullptr; // returns null on success
}

void *MoveableMemoryManager::Alloc(unsigned long flags, size_t size) {
  std::lock_guard<std::recursive_mutex> scoped_lock(GlobalHeapMutex);
  bool zero_alloc = flags & GMEM_ZEROINIT;
  if (flags & GMEM_MOVEABLE) {
    return AddMoveableAllocation(size, zero_alloc);
  } else {
    return AddFixedAllocation(size, zero_alloc);
  }
}

#endif