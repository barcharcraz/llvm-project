// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t
// RUN: %env_asan_opts=allocator_may_return_null=true:windows_hook_rtl_allocators=true %run %t

// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t
// RUN: %env_asan_opts=allocator_may_return_null=true:windows_hook_rtl_allocators=true %run %t


#include <stdio.h>
#include <windows.h>
#include "../defines.h"
#include "globallocal_shared.h"

int main() {
  void *nope = ALLOC(GMEM_FIXED, ((size_t)0) - 1);
  if (nope != nullptr) {
    puts("Fail");
    return 1;
  }
  puts("Pass");
  return 0;
}
// CHECK: Pass
// CHECK-NOT: Fail 