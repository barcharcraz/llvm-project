// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %run %t
// REQUIRES: asan-dynamic-runtime

#include "Windows.h"

char *(*malloc_impl)(size_t) = nullptr;
size_t (*msize_impl)(void *) = nullptr;

int main() {
  HMODULE msvcrt = GetModuleHandleA("msvcrt.dll"); //get a handle to the system's version of msvcrt
  if (!msvcrt) {
    return -1;
  }

  malloc_impl = (char *(*)(size_t))GetProcAddress(msvcrt, "malloc"); //get the special malloc
  msize_impl = (size_t(*)(void *))GetProcAddress(msvcrt, "_msize");  //get the special msize

  if (!malloc_impl || !msize_impl) {
    return -1;
  }

  void *buffer = malloc_impl(42);
  return msize_impl(buffer) == 42 ? 0 : -1;
}
