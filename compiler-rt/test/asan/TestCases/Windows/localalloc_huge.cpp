// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t
// RUN: %env_asan_opts=allocator_may_return_null=true:windows_hook_rtl_allocators=true %run %t
// UNSUPPORTED: asan-64-bits
#include <windows.h>
int main() {
  void *nope = LocalAlloc(LMEM_FIXED, ((size_t)0) - 1);
  return nope != nullptr;
}