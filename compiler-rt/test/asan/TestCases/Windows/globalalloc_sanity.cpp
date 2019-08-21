// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
#include <stdio.h>
#include <windows.h>

int main() {
  char *buffer;
  buffer = (char*)GlobalAlloc(GMEM_FIXED, 32),
  buffer[0] = 'a';
  GlobalFree(buffer);
  puts("Okay");
// CHECK: Okay
}
