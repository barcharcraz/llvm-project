// RUN: %clang_cl_asan /Od %s -Fe%t 
// RUN: not %run %t 2>&1 | FileCheck %s
// REQUIRES: asan-dynamic-runtime
// XFAIL: msvc-host
// vso1239938 Tracked by https://devdiv.visualstudio.com/DevDiv/_workitems/edit/1239938
#include "Windows.h"

char*(*malloc_impl)(size_t) =  nullptr;

int main() {
  HMODULE msvcrt = GetModuleHandleA("msvcrt.dll"); //get a handle to the system's version of msvcrt
  if (!msvcrt)
    return -1;
  malloc_impl = (char*(*)(size_t)) GetProcAddress(msvcrt, "malloc"); //get the special malloc
  if (!malloc_impl)
    return -1;
  char *buffer = (char*)malloc_impl(42);
  HANDLE h = GetProcessHeap();
  return buffer[42] = 42;
}

// CHECK: AddressSanitizer: heap-buffer-overflow