#include "Windows.h"
#include "globallocal_shared.h"
#include <functional>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

template <typename T> struct FuncPair {
  using Type = T *;

  Type Func = nullptr;
  const char *DllFunctionName = "";
};

template <typename AllocFunc, typename SizeFunc, typename FreeFunc,
          typename ReallocFunc>
struct Memory {
  Memory(AllocFunc allocFunc, SizeFunc sizeFunc, FreeFunc freeFunc,
         ReallocFunc reallocFunc, unsigned int flag = 0)
      : Flag(flag) {
    Alloc.Func = allocFunc;
    Size.Func = sizeFunc;
    Free.Func = freeFunc;
    Realloc.Func = reallocFunc;
  }

  template <typename Fn, typename... Args> auto CallFn(Fn &fn, Args... args) {
    if (InstrumentedDll) {
      auto lookupFn = (typename Fn::Type)GetProcAddress(InstrumentedDll,
                                                        fn.DllFunctionName);
      if (lookupFn) {
        return (*lookupFn)(args...);
      } else {
        std::cerr << "No function found " << fn.DllFunctionName << std::endl;
        //CHECK-NOT: {{No function found*}}
        throw std::exception("No function found");
      }
    } else {
      return fn.Func(args...);
    }
  }

  template <typename... Args> auto CallAlloc(Args... args) {
    return CallFn(Alloc, args...);
  }

  template <typename... Args> auto CallRealloc(Args... args) {
    return CallFn(Realloc, args...);
  }

  template <typename... Args> auto CallSize(Args... args) {
    return CallFn(Size, args...);
  }

  template <typename... Args> auto CallFree(Args... args) {
    return CallFn(Free, args...);
  }

  FuncPair<AllocFunc> Alloc;
  FuncPair<SizeFunc> Size;
  FuncPair<FreeFunc> Free;
  FuncPair<ReallocFunc> Realloc;
  unsigned int Flag;
  HINSTANCE InstrumentedDll = nullptr;
  HANDLE Heap = nullptr;

  using IsLockable = std::false_type;
  using IsRecallocable = std::false_type;
};

template <typename AllocFunc, typename SizeFunc, typename FreeFunc,
          typename ReallocFunc, typename LockFunc, typename UnlockFunc,
          typename FlagsFunc, typename HandleFunc>
struct LockableMemory : Memory<AllocFunc, SizeFunc, FreeFunc, ReallocFunc> {
  LockableMemory(AllocFunc allocFunc, SizeFunc sizeFunc, FreeFunc freeFunc,
                 ReallocFunc reallocFunc, LockFunc lockFunc,
                 UnlockFunc unlockFunc, FlagsFunc flagsFunc,
                 HandleFunc handleFunc, unsigned int flag = 0)
      : Memory(allocFunc, sizeFunc, freeFunc, reallocFunc, flag) {
    Lock.Func = lockFunc;
    Unlock.Func = unlockFunc;
    Handle.Func = handleFunc;
    Flags.Func = flagsFunc;
  }

  template <typename... Args> auto CallLock(Args... args) {
    return CallFn(Lock, args...);
  }

  template <typename... Args> auto CallUnlock(Args... args) {
    return CallFn(Unlock, args...);
  }

  template <typename... Args> auto CallHandle(Args... args) {
    return CallFn(Handle, args...);
  }

  template <typename... Args> auto CallFlags(Args... args) {
    return CallFn(Flags, args...);
  }

  FuncPair<LockFunc> Lock;
  FuncPair<UnlockFunc> Unlock;
  FuncPair<HandleFunc> Handle;
  FuncPair<FlagsFunc> Flags;

  using IsLockable = std::true_type;
};

template <typename AllocFunc, typename SizeFunc, typename FreeFunc,
          typename ReallocFunc, typename RecallocFunc>
struct RecallocableMemory : Memory<AllocFunc, SizeFunc, FreeFunc, ReallocFunc> {
  RecallocableMemory(AllocFunc allocFunc, SizeFunc sizeFunc, FreeFunc freeFunc,
                     ReallocFunc reallocFunc, RecallocFunc recallocFunc,
                     unsigned int flag = 0)
      : Memory(allocFunc, sizeFunc, freeFunc, reallocFunc, flag) {
    Recalloc.Func = recallocFunc;
  }

  template <typename... Args> auto CallRecalloc(Args... args) {
    return CallFn(Recalloc, args...);
  }

  FuncPair<RecallocFunc> Recalloc;

  using IsRecallocable = std::true_type;
};

struct GlobalFixed
    : LockableMemory<decltype(GlobalAlloc), decltype(GlobalSize),
                     decltype(GlobalFree), decltype(GlobalReAlloc),
                     decltype(GlobalLock), decltype(GlobalUnlock),
                     decltype(GlobalFlags), decltype(GlobalHandle)> {
  GlobalFixed()
      : LockableMemory(&GlobalAlloc, &GlobalSize, &GlobalFree, &GlobalReAlloc,
                       &GlobalLock, &GlobalUnlock, &GlobalFlags, &GlobalHandle,
                       GMEM_FIXED) {
    Size.DllFunctionName = "GlobalSizeThunk";
    Free.DllFunctionName = "GlobalFreeThunk";
    Realloc.DllFunctionName = "GlobalReAllocThunk";
    Lock.DllFunctionName = "GlobalLockThunk";
    Unlock.DllFunctionName = "GlobalUnlockThunk";
    Handle.DllFunctionName = "GlobalHandleThunk";
    Flags.DllFunctionName = "GlobalFlagsThunk";
  }
};

struct GlobalMoveable
    : LockableMemory<decltype(GlobalAlloc), decltype(GlobalSize),
                     decltype(GlobalFree), decltype(GlobalReAlloc),
                     decltype(GlobalLock), decltype(GlobalUnlock),
                     decltype(GlobalFlags), decltype(GlobalHandle)> {
  GlobalMoveable()
      : LockableMemory(&GlobalAlloc, &GlobalSize, &GlobalFree, &GlobalReAlloc,
                       &GlobalLock, &GlobalUnlock, &GlobalFlags, &GlobalHandle,
                       GHND) {
    Size.DllFunctionName = "GlobalSizeThunk";
    Free.DllFunctionName = "GlobalFreeThunk";
    Realloc.DllFunctionName = "GlobalReAllocThunk";
    Lock.DllFunctionName = "GlobalLockThunk";
    Unlock.DllFunctionName = "GlobalUnlockThunk";
    Handle.DllFunctionName = "GlobalHandleThunk";
    Flags.DllFunctionName = "GlobalFlagsThunk";
  }
};

struct LocalFixed
    : LockableMemory<decltype(LocalAlloc), decltype(LocalSize),
                     decltype(LocalFree), decltype(LocalReAlloc),
                     decltype(LocalLock), decltype(LocalUnlock),
                     decltype(LocalFlags), decltype(LocalHandle)> {
  LocalFixed()
      : LockableMemory(&LocalAlloc, &LocalSize, &LocalFree, &LocalReAlloc,
                       &LocalLock, &LocalUnlock, &LocalFlags, &LocalHandle,
                       LMEM_FIXED) {
    Size.DllFunctionName = "LocalSizeThunk";
    Free.DllFunctionName = "LocalFreeThunk";
    Realloc.DllFunctionName = "LocalReAllocThunk";
    Lock.DllFunctionName = "LocalLockThunk";
    Unlock.DllFunctionName = "LocalUnlockThunk";
    Handle.DllFunctionName = "LocalHandleThunk";
    Flags.DllFunctionName = "LocalFlagsThunk";
  }
};

struct LocalMoveable
    : LockableMemory<decltype(LocalAlloc), decltype(LocalSize),
                     decltype(LocalFree), decltype(LocalReAlloc),
                     decltype(LocalLock), decltype(LocalUnlock),
                     decltype(LocalFlags), decltype(LocalHandle)> {
  LocalMoveable()
      : LockableMemory(&LocalAlloc, &LocalSize, &LocalFree, &LocalReAlloc,
                       &LocalLock, &LocalUnlock, &LocalFlags, &LocalHandle,
                       LHND) {
    Size.DllFunctionName = "LocalSizeThunk";
    Free.DllFunctionName = "LocalFreeThunk";
    Realloc.DllFunctionName = "LocalReAllocThunk";
    Lock.DllFunctionName = "LocalLockThunk";
    Unlock.DllFunctionName = "LocalUnlockThunk";
    Handle.DllFunctionName = "LocalHandleThunk";
    Flags.DllFunctionName = "LocalFlagsThunk";
  }
};

struct HeapMemory : Memory<decltype(HeapAlloc), decltype(HeapSize),
                           decltype(HeapFree), decltype(HeapReAlloc)> {
  HeapMemory() : Memory(&HeapAlloc, &HeapSize, &HeapFree, &HeapReAlloc) {
    Heap = HeapCreate(0, 0, 0);
    Size.DllFunctionName = "HeapSizeThunk";
    Free.DllFunctionName = "HeapFreeThunk";
    Realloc.DllFunctionName = "HeapReAllocThunk";
  }
};

struct NormalMemory
    : RecallocableMemory<decltype(malloc), decltype(_msize), decltype(free),
                         decltype(realloc), decltype(_recalloc)> {
  NormalMemory()
      : RecallocableMemory(&malloc, &_msize, &free, &realloc, &_recalloc) {
    Size.DllFunctionName = "MSizeThunk";
    Free.DllFunctionName = "FreeMemoryThunk";
    Realloc.DllFunctionName = "ReallocThunk";
    Recalloc.DllFunctionName = "RecallocThunk";
  }
};

struct AlignedMemory
    : RecallocableMemory<decltype(_aligned_malloc), decltype(_aligned_msize),
                         decltype(_aligned_free), decltype(_aligned_realloc),
                         decltype(_aligned_recalloc)> {
  AlignedMemory()
      : RecallocableMemory(&_aligned_malloc, &_aligned_msize, &_aligned_free,
                           &_aligned_realloc, &_aligned_recalloc) {
    Size.DllFunctionName = "AlignedMSizeThunk";
    Free.DllFunctionName = "FreeAlignedMemoryThunk";
    Realloc.DllFunctionName = "AlignedReallocThunk";
    Recalloc.DllFunctionName = "AlignedRecallocThunk";
  }
};

struct AlignedOffsetMemory
    : RecallocableMemory<decltype(_aligned_offset_malloc),
                         decltype(_aligned_msize), decltype(_aligned_free),
                         decltype(_aligned_offset_realloc),
                         decltype(_aligned_offset_recalloc)> {
  AlignedOffsetMemory()
      : RecallocableMemory(&_aligned_offset_malloc, &_aligned_msize,
                           &_aligned_free, &_aligned_offset_realloc,
                           &_aligned_offset_recalloc) {
    Size.DllFunctionName = "AlignedMSizeThunk";
    Free.DllFunctionName = "FreeAlignedMemoryThunk";
    Realloc.DllFunctionName = "AlignedOffsetReallocThunk";
    Recalloc.DllFunctionName = "AlignedOffsetRecallocThunk";
  }
};

enum TestType {
  Alloc = 1 << 0,       // Allocate before asan initialization, all tests do
  LockPrior = 1 << 1,   // Lock before asan initialization
  UnlockAfter = 1 << 2, // Unlock after asan initialization before using
  Realloc = 1 << 3,     // Realloc after asan initialzation
  Recalloc = 1 << 4,    // Recalloc after asan initialzation
};

struct MemoryInfo {
  std::string Name = "";
  void *Mem = nullptr;
  TestType Type = TestType::Alloc;
  size_t Alignment = 0;
  size_t Offset = 0;
};

template <typename Type> struct MemoryForManipulating {

  void AddAllocationTest(std::string name, int test, size_t uBytes = 16,
                         size_t alignment = 0, size_t offset = 0) {
    void *mem;
    if constexpr (std::is_same_v<Type, HeapMemory>) {
      mem =
          TypeOfMemory.CallAlloc(TypeOfMemory.Heap, TypeOfMemory.Flag, uBytes);
    }
    if constexpr (std::is_same_v<Type, AlignedMemory>) {
      mem = TypeOfMemory.CallAlloc(uBytes, alignment);
    }
    if constexpr (std::is_same_v<Type, AlignedOffsetMemory>) {
      mem = TypeOfMemory.CallAlloc(uBytes, alignment, offset);
    }
    if constexpr (std::is_same_v<Type, GlobalFixed> ||
                  std::is_same_v<Type, GlobalMoveable> ||
                  std::is_same_v<Type, LocalFixed> ||
                  std::is_same_v<Type, LocalMoveable>) {
      mem = TypeOfMemory.CallAlloc(TypeOfMemory.Flag, uBytes);
    }
    if constexpr (std::is_same_v<Type, NormalMemory>) {
      mem = TypeOfMemory.CallAlloc(uBytes);
    }
    Memory.push_back(
        {name, mem, static_cast<TestType>(TestType::Alloc | test), alignment, offset});
  }

  void LockBeforeASANInit() {
    for (auto &[name, mem, testType, alignment, offset] : Memory) {
      if (testType & TestType::LockPrior) {
        if constexpr (std::is_same_v<Type::IsLockable, std::true_type>) {
          mem = TypeOfMemory.CallLock(mem);
        }
      }
    }
  }

  bool Flags(void *mem) {
    if constexpr (std::is_same_v<Type, GlobalMoveable> ||
                  std::is_same_v<Type, LocalMoveable> ||
                  std::is_same_v<Type, GlobalFixed> ||
                  std::is_same_v<Type, LocalFixed>) {
      if (auto res = TypeOfMemory.CallFlags(mem);
          res == GMEM_INVALID_HANDLE || res == LMEM_INVALID_HANDLE) {
        std::cerr << "Flags Failed." << std::endl;
        //CHECK-NOT: Flags Failed.
        throw std::exception("Flags function failed.");
      }
    }
    return true;
  }

  void Size(void *mem, size_t alignment = 0, size_t offset = 0) {
    size_t result = 0;
    if constexpr (std::is_same_v<Type, HeapMemory>) {
      result = TypeOfMemory.CallSize(TypeOfMemory.Heap, TypeOfMemory.Flag, mem);
    } else if constexpr (std::is_same_v<Type, AlignedMemory> ||
                         std::is_same_v<Type, AlignedOffsetMemory>) {
      result = TypeOfMemory.CallSize(mem, alignment, offset);
    } else {
      result = TypeOfMemory.CallSize(mem);
    }
    if (!result) {
      std::cerr << "Size Failed" << std::endl;
      throw std::exception("Size function failed");
    }
  }

  void *Realloc(void *mem, size_t alignment = 0,
                size_t offset = 0, size_t uBytes = 4096) {
    void *temp = mem;
    if constexpr (std::is_same_v<Type, HeapMemory>) {
      temp = TypeOfMemory.CallRealloc(TypeOfMemory.Heap, TypeOfMemory.Flag, mem,
                                      uBytes);
    }
    if constexpr (std::is_same_v<Type, AlignedMemory>) {
      temp = TypeOfMemory.CallRealloc(mem, uBytes, alignment);
    }
    if constexpr (std::is_same_v<Type, AlignedOffsetMemory>) {
      temp = TypeOfMemory.CallRealloc(mem, uBytes, alignment, offset);
    }
    if constexpr (std::is_same_v<Type, GlobalMoveable> ||
                  std::is_same_v<Type, LocalMoveable>) {
      temp = TypeOfMemory.CallRealloc(mem, uBytes, TypeOfMemory.Flag);
    }
    if constexpr (std::is_same_v<Type, NormalMemory>) {
      temp = TypeOfMemory.CallRealloc(mem, uBytes);
    }
    if (!temp) {
      std::cerr << "Realloc failed" << std::endl;
      throw std::exception("Realloc function failed");
    }
    return temp;
  }

  void *Recalloc(void *mem, size_t alignment = 16,
                 size_t offset = 16, size_t uBytes = 16) {
    constexpr size_t blocks = 100;
    void *temp = mem;
    if constexpr (std::is_same_v<Type, AlignedMemory>) {
      temp = TypeOfMemory.CallRecalloc(mem, blocks, uBytes, alignment);
    }
    if constexpr (std::is_same_v<Type, AlignedOffsetMemory>) {
      temp = TypeOfMemory.CallRecalloc(mem, blocks, uBytes, alignment, offset);
    }
    if constexpr (std::is_same_v<Type, NormalMemory>) {
      temp = TypeOfMemory.CallRecalloc(mem, blocks, uBytes);
    }
    if (!temp) {
      std::cerr << "Recalloc failed" << std::endl;
      throw std::exception("Recalloc function failed");
    }
    return temp;
  }

  void Free(void *mem) {
    if constexpr (std::is_same_v<Type, HeapMemory>) {
      TypeOfMemory.CallFree(TypeOfMemory.Heap, TypeOfMemory.Flag, mem);
    } else {
      TypeOfMemory.CallFree(mem);
    }
  }

  void *Lock(void *mem) {
    void *temp = mem;
    if constexpr (std::is_same_v<Type::IsLockable, std::true_type>) {
      temp = TypeOfMemory.CallLock(mem);
    }
    return temp;
  }

  void *Handle(void *mem) {
    void *temp = mem;
    if constexpr (std::is_same_v<Type::IsLockable, std::true_type>) {
      temp = TypeOfMemory.CallHandle(mem);
    }
    return temp;
  }

  void Unlock(void *mem) {
    if constexpr (std::is_same_v<Type::IsLockable, std::true_type>) {
      TypeOfMemory.CallUnlock(mem);
    }
  }

  void AfterASANInit(HINSTANCE lib) {
    TypeOfMemory.InstrumentedDll = lib;

    for (auto &[name, mem, testType, alignment, offset] : Memory) {
      std::cerr << "Running: " << name << std::endl;
      auto temp = mem;
      auto flagsRes = Flags(temp);
      if (!flagsRes) {
      }

      Size(temp, alignment, offset);

      if (!(testType & TestType::LockPrior)) {
        Lock(temp);
      } else {
        temp = Handle(temp);
      }

      if (testType & TestType::Realloc) {
        auto realloced = Realloc(temp, alignment, offset);
        Size(realloced, alignment, offset);
        Unlock(realloced);
        temp = realloced;
      }

      if (testType & TestType::Recalloc) {
        auto x = Recalloc(temp, alignment, offset);
        Size(x, alignment, offset);
        Unlock(x);
        temp = x;
      }

      if (testType & TestType::UnlockAfter) {
        Unlock(temp);
      }

      Free(temp);
    }
  }

  std::vector<MemoryInfo> Memory{};
  HINSTANCE InstrumentedDll = nullptr;
  Type TypeOfMemory{};
};

template <typename T, typename... Args>
void CreateMemoryPriorToASANInit(T &memType, Args... args) {
  memType.AddAllocationTest("Normal", TestType::Alloc, args...);
  memType.AddAllocationTest("LockPrior", TestType::LockPrior, args...);
  memType.AddAllocationTest("LockPrior & UnlockAfter",
                            TestType::LockPrior | TestType::UnlockAfter,
                            args...);
  memType.AddAllocationTest("Realloc", TestType::Realloc, args...);
  memType.AddAllocationTest("Realloc & LockPrior",
                            TestType::Realloc | TestType::LockPrior, args...);
  memType.AddAllocationTest(
      "Realloc & LockPrior & UnlockAfter",
      TestType::Realloc | TestType::LockPrior | TestType::UnlockAfter, args...);
  memType.AddAllocationTest("Recalloc", TestType::Recalloc, args...);
  memType.AddAllocationTest("Recalloc & LockPrior",
                            TestType::Recalloc | TestType::LockPrior, args...);
  memType.AddAllocationTest("Recalloc & LockPrior & UnlockAfter",
                            TestType::Recalloc | TestType::LockPrior |
                                TestType::UnlockAfter,
                            args...);
  memType.LockBeforeASANInit();
}

// Test if random alignments are handled properly
template <typename MemoryType>
void AddRandomAlignmentAllocations(MemoryForManipulating<MemoryType> &memory) {
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(16, 2056);

  if constexpr (std::is_same_v<MemoryType, AlignedMemory>) {
    for (auto i = 2; i < 4096; i *= 2) {
      std::ostringstream s;
      auto size = dist(rng);
      s << "AlignedMemory size: " << size << " alignment: " << i;
      memory.AddAllocationTest(s.str(), TestType::Alloc, size, i);
    }
  }

  if constexpr (std::is_same_v<MemoryType, AlignedOffsetMemory>) {
    for (auto i = 2; i < 4096; i *= 2) {
      std::ostringstream s;
      auto size = dist(rng);
      s << "AlignedOffsetMemory size: " << size << " alignment: " << i
        << " offset: " << 16;
      memory.AddAllocationTest(s.str(), TestType::Alloc, size, i, 16);
    }
  }
}

template <typename MemoryType>
void AddTests(MemoryForManipulating<MemoryType> &memory) {
  if constexpr (std::is_same_v<MemoryType, AlignedMemory>) {
    CreateMemoryPriorToASANInit(memory, 100, 16);
    AddRandomAlignmentAllocations(memory);
  } else if constexpr (std::is_same_v<MemoryType, AlignedOffsetMemory>) {
    CreateMemoryPriorToASANInit(memory, 200, 16, 5);
    AddRandomAlignmentAllocations(memory);
  } else {
    CreateMemoryPriorToASANInit(memory);
  }
}