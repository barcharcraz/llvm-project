// RUN: %clang_cl_asan -Od %s -Fe%t

#include <iostream>
#include <ppl.h>
#include <windows.h>

using namespace concurrency;

void UserHeapManipulations() {
  // Create user heap and do some operations on it
  HANDLE heap = HeapCreate(0, 0, 0);
  void *ptr = HeapAlloc(heap, 0, 4);
  void *ptr2 = HeapReAlloc(heap, 0, ptr, 0);
  HeapFree(heap, 0, ptr2);
  HeapDestroy(heap);
}

int main(int argc, char *argv[]) {
  concurrency::parallel_for(0, 100, [argc, &argv](int) {
    // Arguments are passed from deadlock_on_process_shutdown_driver.cpp
    if (argc >= 2) {
      UserHeapManipulations();
    }
  });
}