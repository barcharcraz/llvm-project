#pragma once

#define FIXED 0x0000
#define ZEROINIT 0x0040
#define MOVEABLE 0x0002
#define MODIFY 0x0080
#define NOCOMPACT 0x0010
#define NODISCARD 0x0020
#define LOCAL_DISCARDABLE 0x0F00
#define GLOBAL_DISCARDABLE 0x0100
#define GLOBAL_NOT_BANKED 0x1000
#define GLOBAL_SHARE 0x2000 // same as GMEM_DDESHARE and SHARE
#define GLOBAL_NOTIFY 0x4000
#define INVALID_HANDLE 0x8000
#define GLOBAL_VALID_FLAGS 0x7F72
#define LOCAL_VALID_FLAGS 0x0F72

class MoveableAllocEntry {
  // the physical address entry, split so the pointers can be sorted separately
  // for faster ptr->handle lookup.
public:
  void *addr;
  void *handle;
  bool freed;       // set if this the entry is freed, may not be needed
  size_t lockCount; // lock count for this movable section.

  MoveableAllocEntry(size_t handle_index, void *pointer_entry)
      : addr(pointer_entry), lockCount(0), freed(false) {
    handle = reinterpret_cast<void *>(handle_index);
  }

  MoveableAllocEntry(size_t handle_index)
      : addr(nullptr), lockCount(0), freed(false) {
    handle = reinterpret_cast<void *>(handle_index);
  }
};

enum class HeapCaller { GLOBAL, LOCAL };
struct MemoryManagerResources;

class MoveableMemoryManager {
private:
  MoveableMemoryManager();
  ~MoveableMemoryManager();
  void *ReallocHandleToFixed(void *original, bool zero_init);
  void *ReallocFixedToHandle(void *original, bool zero_init);
  void *ReallocFixedToFixed(void *original, size_t new_size, bool zero_init);
  void *ReallocHandleToHandle(void *original, size_t new_size, bool zero_init);
  void *AddMoveableAllocation(size_t size, bool zero_init);
  void *AddFixedAllocation(size_t size, bool zero_init);
  size_t ResolveHandleToIndex(void *handle);
  MoveableAllocEntry *ResolveHandleToTableEntry(void *handle);
  void *TagHandleIndex(size_t);
  bool IsOwnedHandle(void *item);
  bool IsOwnedPointer(void *item);
  void *GetHandleReservation();
  size_t GetHandleTag();

public:
  bool IsOwned(void *item);
  // These functions all take in an untyped identifier, rather
  // than make this more confusing I'll avoid labeling the param
  // 'pointer' or 'handle'; we have to check in the functions anyway.
  void *ResolveHandleToPointer(void *memory_ident);
  void *ResolvePointerToHandle(void *memory_ident);
  size_t GetAllocationSize(void *memory_ident);
  void *IncrementLockCount(void *memory_ident);
  void *DecrementLockCount(void *memory_ident);
  size_t GetLockCount(void *memory_ident);
  void *Free(void *ident);
  void *Alloc(unsigned long flags, size_t size);
  void *ReAllocate(void *ident, size_t flags, size_t size, HeapCaller caller);
  void Purge();
  static MoveableMemoryManager *MoveableMemoryManager::GetInstance();
  static bool MoveableMemoryManager::ManagerIsAlive();
  friend struct ::MemoryManagerResources;

};
