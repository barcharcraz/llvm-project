// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <iostream>
#include <vector>

constexpr int MaxHandleCount =
    0xFFFF; // Max count is hard coded to 0xFFFF for moveable allocations
constexpr int TestHandleCount =
    0x10020; // Some odd count above the max to test handle usage
constexpr int AllocSize = 108;    // Arbitrary size to allocate
std::vector<HGLOBAL> allocations; // Stores all allocations

// This call will result in ASAN crash if anything is invalid
void CheckAllValid() {
  for (auto mem : allocations) {
    GlobalHandle(GlobalLock(mem));
    GlobalUnlock(mem);
  }
}

int main() {
  auto count = 0;
  auto neverDeallocMoveable = GlobalAlloc(GHND, AllocSize);
  auto neverDealloc = GlobalLock(neverDeallocMoveable);
  GlobalHandle(neverDealloc);
  while (count < TestHandleCount) {
    auto newHandle = GlobalAlloc(GHND, AllocSize);
    if (!newHandle) {
      std::cerr << "Out of room.\n";
      CheckAllValid();
      if (count != MaxHandleCount) {
        std::cerr << "Failed.\n";
        return -1;
      }
      // Out of room (0xFFFF), so try to free an appropriate amount to reuse
      for (auto i = 0; i < (TestHandleCount - MaxHandleCount); ++i) {
        GlobalUnlock(allocations.back());
        GlobalFree(allocations.back());
        allocations.pop_back();
      }
      CheckAllValid();
      continue;
    }
    allocations.push_back(newHandle);
    GlobalHandle(GlobalLock(newHandle));
    ++count;

    // always make sure we can reference the first allocation to mimic some OS behavior
    neverDealloc = GlobalLock(neverDeallocMoveable);
    GlobalHandle(neverDealloc);
  }

  CheckAllValid();

  for (auto mem : allocations) {
    GlobalUnlock(mem);
    GlobalFree(mem);
  }

  // CHECK-COUNT-1: Out of room.
  // CHECK: Success.
  // CHECK-NOT: Failure.
  std::cerr << "Success.\n";
  return 0;
}