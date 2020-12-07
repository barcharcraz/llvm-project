// RUN: %clang_cl_asan /Od %s -Fe%t 
// RUN: not %run %t | FileCheck %s
// REQUIRES: asan-dynamic-runtime

#include <Windows.h>
#include <stdio.h>

size_t(*msize_impl)(void*) = nullptr;
void*(*realloc_impl)(void*,size_t) = nullptr;

int main() {
  HMODULE msvcrt = GetModuleHandleA("msvcrt.dll"); //get a handle to the system's version of msvcrt
  if (!msvcrt) {
    return -1;
  }

  realloc_impl = (void*(*)(void*,size_t)) GetProcAddress(msvcrt, "realloc"); //get the special realloc
  msize_impl = (size_t(*)(void*)) GetProcAddress(msvcrt, "_msize"); //get the special msize

  if (!realloc_impl || !msize_impl) {
    if (!realloc_impl) {
      printf("fail (realloc_impl)");
    } else {
      printf("fail (msize_impl)");
    }
    return -1;
  }

  void* buffer = realloc_impl(nullptr ,42);
  if (buffer == nullptr) {
    printf("fail (realloc)\n");
    return -1;
  }
  void* rebuffer = buffer;
  size_t final_size = 128;
  // make the buffer larger until it's actually reallocated
  do {
    final_size *= 2;
    rebuffer = realloc_impl(rebuffer, final_size);
  } while (rebuffer == buffer);

  if (msize_impl(rebuffer) != final_size) { 
    printf("fail (size up)\n");
    return -1;
  }

  buffer = realloc_impl(rebuffer, 8);
  if (msize_impl(buffer) != 8) { 
    printf("fail (size down)\n");
    return -1;
  }

  printf("success");
  return -1;
}

// CHECK-NOT: AddressSanitizer
// CHECK-NOT: fail
// CHECK: success
