// RUN: %clang_cl_asan -Od /std:c++17 %s -Fe%t
// RUN: %clang_cl_asan -LD -Od %p/memory_with_asan_dll.cpp -Fe%t.dll
// RUN: %run %t %t.dll 2>&1 | FileCheck %s
// UNSUPPORTED: clang-static-runtime
// UNSUPPORTED: non-debug-crt
// REQURIES: debug-crt

#include <Windows.h>
#include <algorithm>
#include <stdio.h>
#include <vector>

typedef void(freeMemoryFn)(void *);

struct AllocationDebugHeader {
  void *next, *prev;
  char *file_name;
  int line_number;
  int block_use;
  size_t data_size;
  long req_num;
  unsigned char gap[4];

  AllocationDebugHeader() = delete;
  ~AllocationDebugHeader() = delete;
};

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Must use path to memory_with_asan_dll.dll as argument");
    return 101;
  }
  const char *dllName = argv[1];
  std::vector<void *> mems;
  auto counter = 0;
  while (counter++ < 10000) {
    void *a = HeapAlloc(GetProcessHeap(), 0, 4);
    AllocationDebugHeader *h = reinterpret_cast<AllocationDebugHeader *>(a) - 1;

    // Attempt to find a debug allocation that doesn't quite line up normally
    if (auto it = std::find(mems.begin(), mems.end(), (void *)h); it != mems.end()) {
      mems.push_back(a);
      fputs("Found mismatch.\n", stderr);
      // CHECK: Found mismatch.
      break;
    }
    mems.push_back(a);
  }

  // Load asan and try to free oddly aligned memory
  HINSTANCE getProc = LoadLibrary(dllName);

  if (!getProc) {
    throw std::exception("Unable to load dll");
  }
  auto fn = (freeMemoryFn *)GetProcAddress(getProc, "FreeMemoryThunk");
  if (fn) {
    (*fn)(mems[counter - 1]);
    (*fn)(mems[counter - 2]);
    (*fn)(mems[counter - 3]);
  } else {
    throw std::exception("No function found");
  }
  fputs("Success.\n", stderr);
  // CHECK: Success.
  return 0;
}