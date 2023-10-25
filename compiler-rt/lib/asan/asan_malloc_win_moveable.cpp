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
// Moveable heap allocation manager for Global/Local Alloc interception.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS

#include "asan_malloc_win_moveable.h"
#include "asan_report.h"
#include "asan_stack.h"
#include "asan_win_scoped_lock.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_vector.h"
#include "sanitizer_common/sanitizer_win_immortalize.h"

#define ERROR_NOT_ENOUGH_MEMORY 8L
extern "C" void WINAPI SetLastError(DWORD);
extern "C" DWORD WINAPI GetLastError();

namespace __asan_win_moveable {
    using namespace __asan;

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

template <size_t Size>
struct IndexHandleMap {
    static_assert(((Size + 1) & Size) == 0); // Size must also be a mask.
    static constexpr size_t Mask = Size;
public:
    IndexHandleMap() : _handle_tag((reinterpret_cast<size_t>(&_reservation[0]) + Size) & ~Mask) {}
    // Example:
    // size is 0xFFFF, reservation is 0x1FFFE long
    // reservation starts at 0x12345678 (randomly selected by compiler)
    // reservation ends   at 0x12365676 (start + size)
    //
    // The handle tag will be 0x1235 and valid handles will be from 0x12350000 to 0x1235FFFF.
    // Zone from 0x12345678 to 0x1234FFFF is unused.
    // Zone from 0x12360000 to 0x12365676 is unused.
    //
    // Now, we have a range of "addresses" that we can use as handles that
    // easily map directly to an index into a vector.
    //
    // The reason for this is that we want to be absolutely certain that handle values
    // do not alias any pointers, even ones internal to the implementation.
    //
    // No data is stored in reservation. It is purely to ensure those addresses are not aliased.

    void *IndexToHandle(const size_t index) const {
        return reinterpret_cast<void *>(_handle_tag | index);
    }

    bool IsValidHandle(void *const handle) const {
        return (reinterpret_cast<size_t>(handle) & ~Mask) == _handle_tag;
    }

    size_t HandleToIndex(void *const handle) const {
        CHECK(IsValidHandle(handle));
        return reinterpret_cast<size_t>(handle) & Mask;
    }

private:
    char _reservation[Size * 2]; // Double the size so we are aligned with Size.
    size_t _handle_tag;
};

class TentativeAllocation {
    // Convenience RAII class to handle an allocation that may not be committed
    // to yet since other errors may occur that cause us to want to free this.
public:
    TentativeAllocation(const size_t size, const bool zero_init, BufferedStackTrace &stack)
        : _addr(_AllocMaybeZero(size, zero_init, stack)), _committed(false)
    {
    }

    ~TentativeAllocation() {
        if (!_committed && _addr != nullptr) {
            // This should never fail and cause a stack trace
            // since we just allocated this and haven't returned it
            // to the user yet.
            GET_STACK_TRACE_FREE;
            asan_free(_addr, &stack, FROM_MALLOC);
            SetLastError(ERROR_OUTOFMEMORY);
        }
    }

    TentativeAllocation(const TentativeAllocation &) = delete;
    TentativeAllocation& operator=(const TentativeAllocation &) = delete;

    TentativeAllocation(TentativeAllocation &&rhs) = default;
    TentativeAllocation& operator=(TentativeAllocation &&rhs) = default;

    bool oom() const {
        return _addr == nullptr;
    }

    void commit() {
        _committed = true;
    }

    void *addr() const {
        return _addr;
    }

private:
    static void *_AllocMaybeZero(const size_t size, const bool zero_init, BufferedStackTrace &stack) {
        if (zero_init) {
            return asan_calloc(size, 1, &stack);
        } else {
            return asan_malloc(size, &stack);
        }
    }

    void *_addr;
    bool _committed;
};

void *ReallocMaybeZero(void *const original_addr, const size_t new_size, const bool zero_init, BufferedStackTrace &stack) {
    if (zero_init) {
        return asan_recalloc(original_addr, new_size, 1, &stack);
    } else {
        return asan_realloc(original_addr, new_size, &stack);
    }
}

// -- MoveableMemoryMap and FixedMemoryMap --
// The goal of these classes is to separate the storage details from the behavior details.
// Malloc, free, report errors, and make any other external call in the implementation functions.
// Since locks are only taken in the MemoryMap, this also avoids potential deadlocks from calling
// into other code while holding the MemoryMap locks.

enum class Error {
    None,

    InvalidHandle,   // ERROR_INVALID_HANDLE
    InactiveHandle,  // ^ but handle has existed before
                     // (to differentiate between never-malloc and double-free)
                     // To help with error messages, the return value returned alongside
                     // these errors are the addresses that should be reported on.

    OutOfMemory,     // ERROR_OUTOFMEMORY
    NotEnoughMemory, // ERROR_NOT_ENOUGH_MEMORY
    NotLocked,       // ERROR_NOT_LOCKED
    NoError,         // NO_ERROR
};

struct Result {
    Result() : return_value{} {}
    /* implicit */ Result(void *val) : return_value(val) {}
    Result(void *val, const Error &err) : return_value(val), error(err) {}
    void *return_value;
    Error error = Error::None;
};

struct FlagsResult {
    size_t lock_count;
    bool active;
    Error error = Error::None;
};

class MoveableMemoryMap {
private:
#if _MSC_VER && !defined(__clang__)
    static constexpr void *ReservedAddress = reinterpret_cast<void *>(-1ULL);
#else
    // this frankly _bizarre_ expression activates an extension wherein strict constant checking is disabled in the arms of a ternary operator based on
    // __builtin_constant_p.
    static constexpr void *ReservedAddress = __builtin_constant_p(reinterpret_cast<void*>(-1ULL)) ? reinterpret_cast<void*>(-1ULL) : reinterpret_cast<void*>(-1ULL);
#endif
    struct MoveableAllocation {
        explicit MoveableAllocation(void *const h) : handle(h) {}

        void *const handle; // encodes index into moveable entries
        void *addr = ReservedAddress;
        size_t lock_count = 0;
        bool active = true; // false when in reuse list
    };

    // After a lock is taken GMEM_LOCKCOUNT times via GlobalLock/LocalLock, the lock counter stops incrementing.
    static constexpr size_t LockSaturationLimit = GMEM_LOCKCOUNT;

    using PointerToEntryMap = AddrHashMap<MoveableAllocation *, 11>;

public:
    static constexpr size_t MaxHandleValue = 0xFFFF;

    bool IsOwned(void *const handle_or_addr) {
        return _index_handle_map.IsValidHandle(handle_or_addr) || _QueryPointerEntryMapping(handle_or_addr);
    }

    // HandleReservation is used to be able to allocate space for an allocation entry
    // prior to committing to storing it. This is to detect OOM conditions as early as possible.
    class HandleReservation {
    public:
        // This being thread-safe depends on the fact that the index that refers to a MoveableAllocation
        // is stable. This means that, while we must lock while allocating (the structure itself is not thread-safe),
        // afterwards we can release the lock and assume the MoveableAllocation pointer will remain valid and accurate.
        // This is nice for our special-case fixed->moveable reallocation because then we can complete all the may-fail
        // operations prior to committing without incurring possible deadlocks or races.

        explicit HandleReservation(MoveableMemoryMap &map) : _map(map), _reserved_entry(nullptr) {
            RecursiveScopedLock scoped_lock(_map._lock, _map._thread_id);
            _reserved_entry = _map._NewMoveableAllocation(scoped_lock); // exclusive access to _reserved_entry
        }

        ~HandleReservation() {
            if (!Valid()) {
                RecursiveScopedLock scoped_lock(_map._lock, _map._thread_id);
                _map._DeactivateMoveableAllocation(_reserved_entry, scoped_lock);
            }
        }

        HandleReservation(const HandleReservation &) = delete;
        HandleReservation &operator=(const HandleReservation &) = delete;

        HandleReservation(HandleReservation &&) = default;
        HandleReservation &operator=(HandleReservation &&) = delete;

        bool Valid() const {
            return _reserved_entry != nullptr;
        }

        void *Commit(void *addr) {
            // We still have exclusive access to _reserved_entry here.
            // No lock necessary to add to pointer->handle map since structure is atomic.
            CHECK(addr != nullptr);
            CHECK(Valid());
            CHECK(_reserved_entry->addr == ReservedAddress);
            _reserved_entry->addr = addr;
            _map._AddPointerEntryMapping(_reserved_entry);
            return _reserved_entry->handle;
        }

    private:
        MoveableMemoryMap& _map;
        MoveableAllocation *_reserved_entry;
    };

    HandleReservation Reserve() {
        return HandleReservation(*this);
    }

    Result Add(void *const addr)
    {
        CHECK(addr != nullptr);
        // Returns a handle for a new moveable allocation.
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        MoveableAllocation *const entry = _NewMoveableAllocation(scoped_lock);
        if (entry == nullptr) {
            return {nullptr, Error::NotEnoughMemory};
        }

        entry->addr = addr;
        _AddPointerEntryMapping(entry);
        return entry->handle;
    }

    Result Remove(void *const item)
    {
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return error_result;
        }

        _DeactivateMoveableAllocation(entry, scoped_lock);
        _RemovePointerEntryMapping(entry);
        return entry->addr;
    }

    Result Reallocate(void *const item, void *const new_addr) {
        if (new_addr == nullptr) {
            return Remove(item);
        }

        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return error_result;
        }

        _RemovePointerEntryMapping(entry);

        if (new_addr == nullptr) {
            _DeactivateMoveableAllocation(entry, scoped_lock);
            return nullptr;
        }

        entry->addr = new_addr;
        _AddPointerEntryMapping(entry);
        return entry->handle;
    }

    Result IncrementLockCount(void *const item)
    {
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return error_result;
        }

        if (entry->addr == item) {
            // Must be given handle to lock.
            return item;
        }

        entry->lock_count = (entry->lock_count + 1) % LockSaturationLimit;
        return entry->addr;
    }

    Result DecrementLockCount(void *const item)
    {
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return error_result;
        }

        if (entry->addr == item) {
            // Must be given handle to unlock.
            return item;
        }

        if (entry->lock_count == 0) {
            return {nullptr, Error::NotLocked};
        }

        entry->lock_count--;

        if (entry->lock_count == 0) {
            return {nullptr, Error::NoError};
        }

        // Returns addr if still locked, nullptr if unlocked
        return entry->addr;
    }

    Result PointerToHandle(void *const item) {
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);

        if (entry == nullptr) {
            return error_result;
        }

        if (entry->addr != item) {
            // If input was not a pointer, report invalid handle.
            return {item, Error::InvalidHandle};
        }

        return entry->handle;
    }

    Result HandleToPointer(void *const item) {
        // Succeed for handles and pointers.
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return error_result;
        }

        return entry->addr;
    }

    FlagsResult GetFlags(void *const item) {
        RecursiveScopedLock scoped_lock(_lock, _thread_id);

        const auto [entry, error_result] = _GetEntry(item, scoped_lock);
        if (entry == nullptr) {
            return {0, false, error_result.error};
        }

        return {entry->lock_count, entry->active};
    }

    static void *operator new(size_t, void *p) { return p; } // Immortalize helper

private:
    MoveableAllocation *_NewMoveableAllocation(const RecursiveScopedLock&) {
        // Note that once a moveable allocation is allocated, the index (and therefore handle)
        // is stable. This means that after a handle is allocated, the calling thread has
        // exclusive thread-safe access.

        // First, create a moveable entry up until the maximum handle count.
        // If full, use available slots stored in the handle reuse list.
        // Note that moveable entries never shrinks once allocated.
        const size_t next_available_index = _moveable_entries.Size();

        if (next_available_index <= MaxHandleValue) {
            return _moveable_entries.EmplaceBack(_index_handle_map.IndexToHandle(next_available_index));
        }

        if (_handle_reuse_list.Empty()) {
            return nullptr;
        }

        MoveableAllocation *const reuse_entry = _handle_reuse_list.Back();
        _handle_reuse_list.PopBack();

        // reuse_entry->handle already contains correct handle
        // since it is derived from the index into _moveable_entries
        reuse_entry->addr = ReservedAddress;
        reuse_entry->lock_count = 0;
        reuse_entry->active = true;
        return reuse_entry;
    }

    void _DeactivateMoveableAllocation(MoveableAllocation *const entry, const RecursiveScopedLock&) {
        CHECK(entry != nullptr);
        CHECK(entry->active == true);
        entry->active = false;
        _handle_reuse_list.PushBack(entry);
    }

    struct _GetEntryQueryResult {
        MoveableAllocation *entry;
        Result error_value;
    };

    _GetEntryQueryResult _GetEntry(void *const handle_or_addr, const RecursiveScopedLock&) {
        CHECK(handle_or_addr != nullptr);
        void *const handle = _ToHandle(handle_or_addr);

        const size_t index = _index_handle_map.HandleToIndex(handle);
        if (index >= _moveable_entries.Size()) {
            return {nullptr, {handle_or_addr, Error::InvalidHandle}};
        }

        MoveableAllocation &entry = _moveable_entries[index];
        CHECK(entry.addr != ReservedAddress);

        if (!entry.active) {
            CHECK(entry.addr != nullptr);
            return {nullptr, {entry.addr, Error::InactiveHandle}};
        }

        return {&_moveable_entries[index], {nullptr, Error::None}};
    }

    void *_ToHandle(void *const handle_or_addr) {
        if (_index_handle_map.IsValidHandle(handle_or_addr)) {
            return handle_or_addr;
        }

        MoveableAllocation *const entry = _QueryPointerEntryMapping(handle_or_addr);
        if (entry == nullptr) {
            return nullptr;
        }

        return entry->handle;
    }

    // While no lock is necessary for AddrHashMap, most operations may want to call these
    // under the lock anyway so ensure coordination with other structures.
    void _AddPointerEntryMapping(MoveableAllocation *const entry) {
        // No lock necessary since AddrHashMap provides atomic operations.
        CHECK(entry != nullptr);
        CHECK(entry->addr != nullptr);
        CHECK(_index_handle_map.IsValidHandle(entry->handle));
        PointerToEntryMap::Handle h(&_pointer_to_entry_map, reinterpret_cast<uptr>(entry->addr), false, true);
        CHECK(h.created());
        *h = entry;
    }

    void _RemovePointerEntryMapping(const MoveableAllocation *const entry) {
        // No lock necessary since AddrHashMap provides atomic operations.
        CHECK(entry != nullptr);
        CHECK(entry->addr != nullptr);
        CHECK(_index_handle_map.IsValidHandle(entry->handle));
        PointerToEntryMap::Handle h(&_pointer_to_entry_map, reinterpret_cast<uptr>(entry->addr), true, false);
        CHECK(h.exists());
    }

    MoveableAllocation *_QueryPointerEntryMapping(void *const addr) {
        // No lock necessary since AddrHashMap provides atomic operations.
        PointerToEntryMap::Handle h(&_pointer_to_entry_map, reinterpret_cast<uptr>(addr), false, false);
        if (!h.exists()) {
            return nullptr;
        }
        return *h;
    }

    PointerToEntryMap              _pointer_to_entry_map;
    Vector<MoveableAllocation>     _moveable_entries;
    Vector<MoveableAllocation *>   _handle_reuse_list;
    IndexHandleMap<MaxHandleValue> _index_handle_map;
    SpinMutex                      _lock = {};
    atomic_uint32_t                _thread_id = {};
};

class FixedMemoryMap
{
    // Class to track fixed allocations for GlobalAlloc/LocalAlloc.
    // Instead of tracking double-frees, they can be handled by
    // RtlFreeHeap instead (see GlobalLocalGenericFree in asan_malloc_win.cpp).
    // This gives the advantage that we can avoid locks in FixedMemoryMap and
    // we no longer need to implement a purge functionality.

public:
    using FixedMap = AddrHashMap<bool, 11>;
    // Stores all addresses for fixed allocations by GlobalAlloc/LocalAlloc.

    bool IsOwned(void *addr) {
        // Return true if this is an address that should be tracked here.
        FixedMap::Handle h(&_active, reinterpret_cast<uptr>(addr), false, false);
        return h.exists();
    }

    Result Add(void *addr) {
        CHECK(addr != nullptr);
        FixedMap::Handle h(&_active, reinterpret_cast<uptr>(addr), false, true);
        CHECK(h.created());
        return addr;
    }

    Result Remove(void *addr) {
        if (addr == nullptr) {
            return nullptr;
        }

        FixedMap::Handle h(&_active, reinterpret_cast<uptr>(addr), true, false);
        // Currently shouldn't be able to error, since this only handles
        // frees for addresses that are owned, and if it's owned it must be here.
        if (!h.exists()) {
            return {addr, Error::InvalidHandle};
        }

        return addr;
    }

    // Implementation Note: Actual GlobalReAlloc for Fixed pointers behavior depends on the underlying
    // Heap implementation and how it responds to HEAP_REALLOC_IN_PLACE_ONLY. For example, LFH heap will
    // reject all requests. Segment heap will allow keeping the same size, but not growing/shrinking.
    // The ASAN implementation currently permits a new address to be assigned since our allocator does
    // not support "in-place-only realloc".
    Result Reallocate(void *handle, void *new_addr) {
        CHECK(handle != nullptr);
        const auto r = Remove(handle);
        if (r.error == Error::None && new_addr != nullptr) {
            return Add(new_addr);
        }
        return r;
    }

    Result IncrementLockCount(void *addr) {
        // Via MSDN, fixed addresses always return themselves.
        if (!IsOwned(addr)) {
            return {addr, Error::InvalidHandle};
        }
        return addr;
    }

    Result DecrementLockCount(void *addr) {
        // Via MSDN, fixed addresses always return true (still locked).
        if (!IsOwned(addr)) {
            return {addr, Error::InvalidHandle};
        }
        return addr;
    }

    Result HandleToPointer(void *handle) {
        // Handles are the addresses for fixed allocations.
        if (!IsOwned(handle)) {
            return {handle, Error::InvalidHandle};
        }
        return handle;
    }

    Result PointerToHandle(void *addr) {
        // There is no corresponding handle for fixed allocations.
        if (!IsOwned(addr)) {
            return {addr, Error::InvalidHandle};
        }
        return addr;
    }

    FlagsResult GetFlags(void *addr) {
        if (!IsOwned(addr)) {
            return {0, false, Error::InvalidHandle};
        }

        return {0, true};
    }

    static void *operator new(size_t, void *p) { return p; } // Immortalize helper

private:
    FixedMap _active;
};

// Immortal Singletons
MoveableMemoryMap &GetMoveableMemoryMap() {
    return immortalize<MoveableMemoryMap>();
}

FixedMemoryMap &GetFixedMemoryMap() {
    return immortalize<FixedMemoryMap>();
}

static void ReportInvalidHandle(void *item, BufferedStackTrace &stack) {
    ReportGenericError(stack.trace_buffer[0], stack.top_frame_bp, reinterpret_cast<uptr>(&stack), reinterpret_cast<uptr>(item), false, sizeof(void *), 0, false);
}

// Visit selects which memory map should be used to store information on the allocation
// either based on the address given or whether the MOVEABLE flag is used.
template <typename Function>
static auto Visit(void *const item, const Function& f) -> decltype(f(GetMoveableMemoryMap())) {
    if (GetMoveableMemoryMap().IsOwned(item)) {
        return f(GetMoveableMemoryMap());
    }
    return f(GetFixedMemoryMap());
}

template <typename Function>
static auto Visit(const unsigned long flags, const Function& f) {
    if (flags & MOVEABLE) {
        return f(GetMoveableMemoryMap());
    }
    return f(GetFixedMemoryMap());
}

// __asan_win_moveable Interface
bool IsOwned(void *const item) {
    // An address or handle is "owned" if this implementation should take care of handling
    // frees and other requests. For moveable memory, this means anything in the reservation range
    // and known pointer addresses.
    return GetMoveableMemoryMap().IsOwned(item) || GetFixedMemoryMap().IsOwned(item);
}

template <typename MemoryMap>
static void *ResolvePointerToHandleImpl(MemoryMap &memory_map, void *const item, BufferedStackTrace &stack) {
    const auto [handle, error_code] = memory_map.PointerToHandle(item);

    if (error_code == Error::InvalidHandle || error_code == Error::InactiveHandle) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportInvalidHandle(handle, stack);
        return nullptr;
    }

    return handle;
}

void *ResolvePointerToHandle(void *const item, BufferedStackTrace &stack) {
    if (item == nullptr) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportInvalidHandle(item, stack);
        return nullptr;
    }

    return Visit(item, [=, &stack](auto& memory_map){ return ResolvePointerToHandleImpl(memory_map, item, stack); });
}

template <typename MemoryMap>
static size_t GetAllocationSizeImpl(MemoryMap &memory_map, void *const item, BufferedStackTrace &stack) {
    const auto [addr, error_code] = memory_map.HandleToPointer(item);

    if (error_code == Error::InvalidHandle || error_code == Error::InactiveHandle) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportMallocUsableSizeNotOwned(reinterpret_cast<uptr>(addr), &stack);
        return 0;
    }

    CHECK(error_code == Error::None);
    CHECK(addr != nullptr);

    return asan_malloc_usable_size(addr, stack.trace_buffer[0], stack.top_frame_bp);
}

size_t GetAllocationSize(void *const item, BufferedStackTrace &stack) {
    if (item == nullptr) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportInvalidHandle(item, stack);
        return 0;
    }

    return Visit(item, [=, &stack](auto& memory_map){ return GetAllocationSizeImpl(memory_map, item, stack); });
}

template <typename MemoryMap>
static void *IncrementLockCountImpl(MemoryMap &memory_map, GlobalLocalLock func, void *const item, BufferedStackTrace &stack) {
    auto [result, error_code] = memory_map.IncrementLockCount(item);

    if (error_code == Error::InvalidHandle || error_code == Error::InactiveHandle) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportInvalidHandle(result, stack);
        return nullptr;
    }

    CHECK(error_code == Error::None);
    return result;
}

void *IncrementLockCount(void *const item, GlobalLocalLock func, BufferedStackTrace &stack) {
    if (item == nullptr) {
        SetLastError(ERROR_INVALID_HANDLE);
        ReportInvalidHandle(item, stack);
        return nullptr;
    }

    return Visit(item, [=, &stack](auto& memory_map){ return IncrementLockCountImpl(memory_map, func, item, stack); });
}

template <typename MemoryMap>
static bool DecrementLockCountImpl(MemoryMap &memory_map, GlobalLocalUnlock func, void *const item, BufferedStackTrace &stack) {
    auto [result, error_code] = memory_map.DecrementLockCount(item);

    switch (error_code) {
        case Error::InvalidHandle:
        case Error::InactiveHandle:
        {
            SetLastError(ERROR_INVALID_HANDLE);
            ReportInvalidHandle(result, stack);
            return false;
        }
        case Error::NotLocked:
            SetLastError(ERROR_NOT_LOCKED);
            break;
        case Error::NoError:
            SetLastError(NO_ERROR);
            break;
        default:
            CHECK(error_code == Error::None);
            break;
    }
    return result;
}

bool DecrementLockCount(void *const item, GlobalLocalUnlock func, BufferedStackTrace &stack) {
    if (item == nullptr) {
        ReportInvalidHandle(item, stack);
        return true;
    }

    return Visit(item, [=, &stack](auto& memory_map){ return DecrementLockCountImpl(memory_map, func, item, stack); });
}

template <typename MemoryMap>
static void *FreeImpl(MemoryMap &memory_map, void *const item, BufferedStackTrace &stack) {
    const auto [result, error_code] = memory_map.Remove(item);

    if (error_code == Error::InvalidHandle) {
        // TODO: Support address description for handles.
        ReportFreeNotMalloced(reinterpret_cast<uptr>(result), &stack);
        return item; // Free returns parameter on failure.
    }

    if (error_code == Error::InactiveHandle) {
        // TODO: Support address description for handles.
        ReportDoubleFree(reinterpret_cast<uptr>(result), &stack);
        return item; // Free returns parameter on failure.
    }

    CHECK(error_code == Error::None);

    asan_free(result, &stack, FROM_MALLOC);
    return nullptr; // Free returns nullptr on success.
}

void *Free(void *const item, BufferedStackTrace &stack) {
    if (item == nullptr) {
        // Even though this is an invalid handle, we shouldn't consider this an error.
        // It is common to skip the null check for passing to null since most
        // free implementations no-op on nullptr.
        return nullptr;
    }
    return Visit(item, [=, &stack](auto& memory_map){ return FreeImpl(memory_map, item, stack); });
}

template <typename MemoryMap>
static void *AllocImpl(MemoryMap &memory_map, TentativeAllocation &new_region) {
    const auto [new_handle, error_code] = memory_map.Add(new_region.addr());

    if (error_code == Error::NotEnoughMemory) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }

    CHECK(error_code == Error::None);
    CHECK(new_handle != nullptr);

    new_region.commit();
    return new_handle;
}

void *Alloc(const unsigned long flags, const size_t size, BufferedStackTrace &stack) {
    TentativeAllocation new_region(size, flags & ZEROINIT, stack);
    if (new_region.oom()) {
        SetLastError(ERROR_OUTOFMEMORY);
        return nullptr;
    }
    return Visit(flags, [&new_region](auto& memory_map){ return AllocImpl(memory_map, new_region); });
}

template <typename MemoryMap>
static unsigned int FlagsImpl(MemoryMap &memory_map, void *item,
                              BufferedStackTrace &stack) 
{
    FlagsResult flags = memory_map.GetFlags(item);
    if (flags.error != Error::None && flags.error != Error::InactiveHandle) {
        return INVALID_HANDLE;
    }
    unsigned int result = 0;
    result |= GMEM_LOCKCOUNT & flags.lock_count;
    if (!flags.active) {
        result |= GMEM_DISCARDED;
    }
    return result;
}
unsigned int Flags(void *item, BufferedStackTrace &stack) {
    if (item == nullptr) {
        ReportInvalidHandle(item, stack);
        return INVALID_HANDLE;
    }
    return Visit(item, [=, &stack](auto &memory_map) {
      return FlagsImpl(memory_map, item, stack);
    });
}

template <typename MemoryMap>
static void *ReAllocateImpl(MemoryMap &memory_map, void *const item, const unsigned long flags, const size_t size, BufferedStackTrace &stack) {
    const auto [existing_addr, error_code] = memory_map.HandleToPointer(item);

    // Handle all errors first, because a reallocation is not undo-able.
    if (error_code == Error::InvalidHandle) {
        // TODO: Support address description for handles.
        ReportFreeNotMalloced(reinterpret_cast<uptr>(existing_addr), &stack);
        return nullptr;
    }

    if (error_code == Error::InactiveHandle) {
        // TODO: Support address description for handles.
        ReportDoubleFree(reinterpret_cast<uptr>(existing_addr), &stack);
        return nullptr;
    }

    // Handle may be freed out from underneath us while we're reallocating.
    void *const new_region = ReallocMaybeZero(existing_addr, size, flags & ZEROINIT, stack);

    if (new_region == existing_addr) {
        // Reallocation was completed in place, no need to update structures.
        return item;
    }

    const auto [realloced_result, realloc_error_code] = memory_map.Reallocate(item, new_region); // removes if new_region == nullptr

    if (new_region == nullptr) {
        if (size != 0) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        return nullptr;
    }

    // We already handled these errors, but we still need to handle failures if the address was freed in between.
    // In that case, returning nullptr (indicating the previous handle is valid) works to resolve the race.

    if (error_code == Error::InvalidHandle) {
        // TODO: Support address description for handles.
        ReportFreeNotMalloced(reinterpret_cast<uptr>(realloced_result), &stack);
        return nullptr;
    }

    if (error_code == Error::InactiveHandle) {
        // TODO: Support address description for handles.
        ReportDoubleFree(reinterpret_cast<uptr>(realloced_result), &stack);
        return nullptr;
    }

    CHECK(realloc_error_code == Error::None);
    CHECK(realloced_result != nullptr);

    return realloced_result;
}

void *ReAllocate(void *const item, const unsigned long flags, const size_t size, const HeapCaller caller, BufferedStackTrace &stack) {
    if (item == nullptr) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }

    // Edge case: MODIFY flag, changing Fixed -> Moveable for GlobalReAlloc
    if (flags & MODIFY) {
        // MODIFY means only edit the flags for the allocation, don't actually re-allocate.
        // However, the only relevant flag is MOVEABLE, and only GlobalReAlloc permits the
        // fixed -> moveable modification. The 'size' argument is ignored here.

        if (flags & MOVEABLE && caller == HeapCaller::GLOBAL && GetFixedMemoryMap().IsOwned(item)) {
            GET_CURRENT_PC_BP;
            const size_t original_size = asan_malloc_usable_size(item, pc, bp);

            TentativeAllocation new_region(original_size, flags & ZEROINIT, stack);

            if (new_region.oom()) {
                SetLastError(ERROR_OUTOFMEMORY);
                return nullptr;
            }

            auto reserved_handle = GetMoveableMemoryMap().Reserve();

            if (!reserved_handle.Valid()) {
                SetLastError(ERROR_OUTOFMEMORY);
                return nullptr;
            }

            REAL(memcpy)(new_region.addr(), item, original_size);

            if (FreeImpl(GetFixedMemoryMap(), item, stack) != nullptr) {
                return nullptr;
            }

            new_region.commit();
            return reserved_handle.Commit(new_region.addr());
        }

        // Otherwise, nothing to do for MODIFY flag.
        return item;
    }

    // Flags do not determine whether it's fixed or moveable for realloc - the original address does.
    return Visit(item, [=, &stack](auto& memory_map) { return ReAllocateImpl(memory_map, item, flags, size, stack); });
}

} // namespace __asan_win_moveable

#endif // SANITIZER_WINDOWS
