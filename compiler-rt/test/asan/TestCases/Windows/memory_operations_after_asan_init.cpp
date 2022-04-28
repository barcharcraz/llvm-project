// RUN: %clang -Od %s -Fe%t
// RUN: %clang_cl_asan -LD -Od %p/memory_with_asan_dll.cpp -Fe%t.dll
// RUN: %run %t %t.dll
// UNSUPPORTED: clang-static-runtime

#include "Windows.h"
#include "malloc.h"
#include <iostream>
#include <random>
#include <stdio.h>
#include <vector>

typedef void(freeMemoryFn)(int *);
typedef void(reallocFn)(int *, size_t);
typedef void(recallocFn)(int *, size_t, size_t);
typedef void(alignedReallocFn)(int *, size_t, size_t);
typedef void(alignedRecallocFn)(int *, size_t, size_t, size_t);

template <typename Fn, typename... Args>
void CallFn(HINSTANCE dll, const char *functionName, Args... args) {
  auto fn = (Fn *)GetProcAddress(dll, functionName);
  if (fn) {
    (*fn)(args...);
  } else {
    throw std::exception("No function found");
  }
}

static void FreeMemoryInAnotherDll(const char *dllName) {
  HANDLE heap = HeapCreate(0, 0, 0);

  // TODO: We should in the future report use of one of the below functions and not using the corresponding *Free
  auto heapAllocPriorToAsan = (int *)HeapAlloc(heap, 0, 16);
  auto globalAllocPriorToAsan = (int *)GlobalAlloc(GMEM_FIXED, 16);
  auto localAllocPriorToAsan = (int *)LocalAlloc(LMEM_FIXED, 16);
  auto pointer = (int *)malloc(16);
  auto pointerToRealloc = (int *)malloc(16);
  auto pointerToRecalloc = (int *)malloc(16);

  // aligned memory
  auto alignedPtr = (int *)_aligned_malloc(100, 16);
  auto alignedToRealloc = (int *)_aligned_malloc(100, 16);
  auto alignedToRecalloc = (int *)_aligned_malloc(100, 16);
  auto alignedOffset = (int *)_aligned_offset_malloc(200, 16, 5);
  auto alignedOffsetAgain = (int *)_aligned_offset_malloc(500, 8, 17);

  std::vector<int *> ptrs;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(1, 2056);

  // try random alignments and sizes
  for (auto i = 2; i < 4096; i *= 2) {
    ptrs.emplace_back((int *)_aligned_malloc(dist(rng), i));
  }

  HINSTANCE getProc = LoadLibrary(dllName);

  if (!getProc) {
    throw std::exception("Unable to load dll");
  }

  // normal memory operations
  CallFn<freeMemoryFn>(getProc, "FreeMemory", heapAllocPriorToAsan);
  CallFn<freeMemoryFn>(getProc, "FreeMemory", globalAllocPriorToAsan);
  CallFn<freeMemoryFn>(getProc, "FreeMemory", localAllocPriorToAsan);
  CallFn<freeMemoryFn>(getProc, "FreeMemory", pointer);
  CallFn<reallocFn>(getProc, "Realloc", pointerToRealloc, 100);
  CallFn<recallocFn>(getProc, "Recalloc", pointerToRecalloc, 8, 16);

  // aligned memory operations
  CallFn<freeMemoryFn>(getProc, "FreeAlignedMemory", alignedPtr);
  CallFn<freeMemoryFn>(getProc, "FreeAlignedMemory", alignedOffset);
  CallFn<freeMemoryFn>(getProc, "FreeAlignedMemory", alignedOffsetAgain);
  CallFn<alignedReallocFn>(getProc, "AlignedRealloc", alignedToRealloc, 100, 16);
  CallFn<alignedRecallocFn>(getProc, "AlignedRecalloc", alignedToRecalloc, 8, 64, 16);
  for (auto &element : ptrs) {
    CallFn<freeMemoryFn>(getProc, "FreeAlignedMemory", element);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Must use path to memory_with_asan_dll.dll as argument");
    return 101;
  }
  const char *dllName = argv[1];
  FreeMemoryInAnotherDll(dllName);
  fputs(" Success.\n", stderr);
  return 0;
}