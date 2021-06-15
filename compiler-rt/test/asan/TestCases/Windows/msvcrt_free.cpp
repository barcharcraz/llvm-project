// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %run %t | FileCheck %s
// REQUIRES: asan-dynamic-runtime

#include <Windows.h>
#include <stdio.h>

char *(*malloc_impl)(size_t) = nullptr;
void (*free_impl)(void *) = nullptr;

int main() {
  HMODULE msvcrt = GetModuleHandleA("msvcrt.dll"); //get a handle to the system's version of msvcrt
  if (!msvcrt) {
    printf("fail (GetModuleHandle)\n");
    return -1;
  }

  malloc_impl = (char *(*)(size_t))GetProcAddress(msvcrt, "malloc"); //get the special malloc
  free_impl = (void (*)(void *))GetProcAddress(msvcrt, "free");      //get the special free

  if (!malloc_impl || !free_impl) {
    printf("fail (GetProcAddress)\n");
    return -1;
  }

  char *buffer = (char *)malloc_impl(42);
  free_impl(buffer);
  printf("success\n");
  return 0;
}

// CHECK-NOT: AddressSanitizer
// CHECK-NOT: fail
// CHECK: success
