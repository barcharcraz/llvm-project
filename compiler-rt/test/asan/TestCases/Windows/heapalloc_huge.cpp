// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t
// RUN: %env_asan_opts=allocator_may_return_null=true:windows_hook_rtl_allocators=true %run %t
// UNSUPPORTED: asan-64-bits
#include <stdio.h>
#include <windows.h>
int main() {
  void *nope = HeapAlloc(GetProcessHeap(), 0, ((size_t)0) - 1);
  if (nope != nullptr) {
    puts("Fail");
    return 1;
  }
  puts("Pass");
  return 0;
}
// CHECK: Pass
// CHECK-NOT: Fail 

