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
#include <errhandlingapi.h>

#include <atomic>
#include <cassert>
#include <cstdio>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <vector>

#include "asan_malloc_win_moveable.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

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

struct MemoryManagerResources {
  /* MoveableManagerResources:

    Making a class to wrap up these resources so that:

    a) we don't need to include these in the header, since we don't want to
    poison other files' imports.

    b) We can be sure of the destructor ordering. We
    want the manager to be last so that we can be aware of the other items being
    destroyed before their resources disappear.

    We've encountered an issue where GlobalFree can be called *after* the
    destructor for this class is called. This is undefined behavior for sure,
    it's occuring late in the process teardown so the best we can do is just
    pass back to the original allocator. This seems to be good enough for most
    cases, but it could potentially lead to passing asan-ized pointers into
    GlobalFree.

    The only item that has a wrapped GetInstance function is the
    MoveableMemoryManager because it is the only item used outside this file.
  */
  std::vector<MoveableAllocEntry *> MoveableEntires;
  std::queue<MoveableAllocEntry *> HandleReuseList;

  /* To resolve pointer->handle_entry quickly, create a map to track pointer to
   * handle_entry associations. */
  std::unordered_map<void *, MoveableAllocEntry *> PointerToHandleMap;

  /* The ReAlloc case needs to call Free, which also grabs the mutex.
   * rather then have some bool to skip the lock in some cases this seems
   * like an appropriate case for a recursive lock */
  std::recursive_mutex GlobalHeapMutex;
  MoveableMemoryManager MoveableManager;
};

static MemoryManagerResources MoveableManagerWrapper;
MoveableMemoryManager *MoveableMemoryManager::GetInstance() {
  return &(MoveableManagerWrapper.MoveableManager);
}

/* This const will be both our handle limit and a mask to remove the handle
 * tag*/
constexpr size_t GlobalLocalHeapHandleLimit = 0xFFFF;
/* To track whether a fixed pointer is freed or not, we can use 0 and -1 as
 * markers for the fixed pointers.*/
const MoveableAllocEntry *IsFixedPointer = nullptr;
const MoveableAllocEntry *IsFreedFixedPointer =
    reinterpret_cast<MoveableAllocEntry *>(~__sanitizer::uptr{0});
bool HandleIsActiveHandle(MoveableAllocEntry *ident) {
  return ident != IsFixedPointer && ident != IsFreedFixedPointer;
}

/* Make this reservation static, but to ensure it's aligned apply the
 * aligned_malloc technique of reserving twice the amount of space and using the
 * first aligned address within that reservation as element 0. */
static char AlignedHandleReservation[GlobalLocalHeapHandleLimit * 2];

/* The following item will end up being set to the first aligned address in
   AlignedHandleReservation */
static void *MoveableHandleTag;

// ignore dll linkage warning: we are defining our own versions in
// asan_malloc_win.
#pragma warning(push)
#pragma warning(disable : 4273)

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

static __sanitizer::atomic_uint8_t managerIsAlive = {};

/* Interface for checking whether this manager is alive externally.
   For some interceptors it makes more sense to check at the point of
   interception.
*/
bool MoveableMemoryManager::ManagerIsAlive() {
  return __sanitizer::atomic_load_relaxed(&managerIsAlive);
}

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
  __sanitizer::atomic_store_relaxed(&managerIsAlive, (unsigned char)1);
}

MoveableMemoryManager::~MoveableMemoryManager() {
  __sanitizer::atomic_store_relaxed(&managerIsAlive, (unsigned char)0);
}

void MoveableMemoryManager::Purge() {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  // pointer to handle map first, find fixed free items and clear them.
  std::unordered_map<void *, MoveableAllocEntry *>::iterator iter =
      MoveableManagerWrapper.PointerToHandleMap.begin();
  std::vector<void *> removal_list = {};
  for (auto &kv : MoveableManagerWrapper.PointerToHandleMap) {
    if (kv.first == IsFreedFixedPointer) {
      removal_list.push_back(kv.first);
    }
  }
  for (auto &freed_pointer : removal_list) {
    MoveableManagerWrapper.PointerToHandleMap.erase(freed_pointer);
  }

  // Moveable Entries already free their backing memory, we just cleaned up the
  // leftovers in the fixed area, the handle reuse list will remain the same.
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

#define HANDLE_OUT_OF_MEMORY(x)        \
  do                                   \
    if (!x) {                          \
      SetLastError(ERROR_OUTOFMEMORY); \
      return nullptr;                  \
    }                                  \
  while (0)

void *MoveableMemoryManager::TagHandleIndex(size_t index) {
  return (void *)(GetHandleTag() | index);
}

void *MoveableMemoryManager::AddMoveableAllocation(size_t size,
                                                   bool zero_init) {
  void *new_region = AllocMaybeZero(size, zero_init);
  HANDLE_OUT_OF_MEMORY(new_region);
  size_t next_available_handle = MoveableManagerWrapper.MoveableEntires.size();
  if (next_available_handle <= 0xFFFF) {
    MoveableAllocEntry *new_handle = new (std::nothrow)
        MoveableAllocEntry(next_available_handle, new_region);
    if (new_handle == nullptr) {
      free(new_region);
      SetLastError(ERROR_OUTOFMEMORY);
      return nullptr;
    }
    MoveableManagerWrapper.MoveableEntires.push_back(new_handle);
    MoveableManagerWrapper.PointerToHandleMap[new_region] = new_handle;
    return TagHandleIndex(next_available_handle);
  }
  if (MoveableManagerWrapper.HandleReuseList.empty()) {
    free(new_region);
    SetLastError(ERROR_OUTOFMEMORY);
    return nullptr;
  }
  MoveableAllocEntry *reuseEntry =
      MoveableManagerWrapper.HandleReuseList.front();
  MoveableManagerWrapper.HandleReuseList.pop();
  // reuseEntry->handle value remains the same
  reuseEntry->freed = false;
  reuseEntry->addr = new_region;
  reuseEntry->lockCount = 0;
  return TagHandleIndex((size_t)(reuseEntry->handle));
}

void *MoveableMemoryManager::AddFixedAllocation(size_t size, bool zero_init) {
  void *new_region = AllocMaybeZero(size, zero_init);
  HANDLE_OUT_OF_MEMORY(new_region);
  MoveableManagerWrapper.PointerToHandleMap[new_region] =
      const_cast<MoveableAllocEntry *>(IsFixedPointer);
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

MoveableAllocEntry *MoveableMemoryManager::ResolveHandleToTableEntry(
    void *handle) {
  size_t index = ResolveHandleToIndex(handle);
  if (index >= MoveableManagerWrapper.MoveableEntires.size()) {
    SetLastError(ERROR_INVALID_HANDLE);
    return nullptr;
  }
  return MoveableManagerWrapper.MoveableEntires.at(index);
}

// TODO: Resolve what needs to happen for these error cases.
//       Windows just crashes inconsistently on some of these.
//       A report would be nice...
void *MoveableMemoryManager::ResolvePointerToHandle(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);

  if (IsOwnedPointer(ident)) {
    MoveableAllocEntry *handle_entry =
        MoveableManagerWrapper.PointerToHandleMap.at(ident);
    if (HandleIsActiveHandle(handle_entry)) {
      return handle_entry->handle;
    }
    return nullptr;
  }
  CHECK(0 &&
        "Untracked pointer passed into "
        "MoveableMemoryManager::ResolvePointerToHandle");
  return nullptr;
}

// These might need a refactor but I'll wait until they're finished.
// TODO: overflows and underflows
void *MoveableMemoryManager::IncrementLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    if (!entry) {
      return nullptr;
    }
    entry->lockCount++;  // <- could overflow
    return ResolveHandleToPointer(ident);
  } else if (IsOwnedPointer(ident)) {
    return ident;  // for fixed memory the pointer is just returned (MSDN)
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
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  void *ptr;
  if (IsOwnedHandle(memory_ident)) {
    ptr = ResolveHandleToPointer(memory_ident);
  } else if (IsOwnedPointer(memory_ident)) {
    ptr = memory_ident;
  } else {
    CHECK(0 &&
          "Memory ID passed to MoveableMemoryManager::GetAllocationSize "
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
  MoveableAllocEntry *handle_entry = ResolveHandleToTableEntry(original);
  void *ptr = handle_entry->addr;
  void *new_ptr = ReallocFixedToFixed(ptr, new_size, zero_init);
  if (!new_ptr) {
    return nullptr;
  }
  if (new_ptr != ptr) {
    // New backing memory, the old pointer is invalid so we need to update our
    // table to remember this
    MoveableManagerWrapper.PointerToHandleMap[new_ptr] = handle_entry;
    handle_entry->addr = new_ptr;

    /* leave the pointer entry, since we want to know this is owned still, if
     * it's passed into a function it will be treated like a fixed pointer, and
     * will get passed to an asan_function to get reported on. It will have been
     * freed & quarantined at this point. */
    MoveableManagerWrapper.PointerToHandleMap[ptr] =
        const_cast<MoveableAllocEntry *>(IsFreedFixedPointer);
  }
  return original;
}

void *MoveableMemoryManager::DecrementLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
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
    return ident;  // for fixed memory the pointer is just returned (MSDN)
  } else {
    CHECK(0 && "Wild pointer passed into [Global|Local]Unlock");
  }
  return nullptr;
}

size_t MoveableMemoryManager::GetLockCount(void *ident) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    return entry->lockCount;
  } else if (IsOwnedPointer(ident)) {
    return 0;  // lock count is always 0 for pointers according to MSDN.
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
  return MoveableManagerWrapper.PointerToHandleMap.find(item) !=
         MoveableManagerWrapper.PointerToHandleMap.end();
}

bool MoveableMemoryManager::IsOwned(void *item) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  return MoveableMemoryManager::ManagerIsAlive() &&
         (IsOwnedPointer(item) || IsOwnedHandle(item));
}

void *MoveableMemoryManager::ReAllocate(void *ident, size_t flags, size_t size,
                                        HeapCaller caller) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
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
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  if (IsOwnedHandle(ident)) {
    void *backing_memory = ResolveHandleToPointer(ident);
    free(backing_memory);
    MoveableAllocEntry *entry = ResolveHandleToTableEntry(ident);
    CHECK(entry != nullptr);
    MoveableManagerWrapper.PointerToHandleMap[backing_memory] =
        const_cast<MoveableAllocEntry *>(IsFreedFixedPointer);

    /* NOTE: Lock count is not affected by free
             you can even get the lock count of the handle after
             the base memory is freed.
    */
    entry->freed = true;
    MoveableManagerWrapper.HandleReuseList.push(entry);
    return nullptr;
  }

  /* If this is a bad free it will be reported on. */
  free(ident);
  return nullptr;  // returns null on success
}

void *MoveableMemoryManager::Alloc(unsigned long flags, size_t size) {
  std::lock_guard<std::recursive_mutex> scoped_lock(
      MoveableManagerWrapper.GlobalHeapMutex);
  bool zero_alloc = flags & GMEM_ZEROINIT;
  if (flags & GMEM_MOVEABLE) {
    return AddMoveableAllocation(size, zero_alloc);
  } else {
    return AddFixedAllocation(size, zero_alloc);
  }
}

#endif