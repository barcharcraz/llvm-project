// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 

#include <windows.h>

int main() {
  char *buffer;
  buffer = (char*)GlobalAlloc(GMEM_FIXED, 32),
  buffer[33] = 'a';
// CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
}
