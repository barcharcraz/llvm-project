// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1
// XFAIL: asan-64-bits
#include <cassert>
#include <windows.h>

int main() {
  void *allocation = HeapAlloc(GetProcessHeap(), 0, 10);
  assert(allocation != 0);
  HeapFree(GetProcessHeap(), 0, (void *)0);
//TODO: This should actually trigger a report, since Free(NULL) is undefined for windows.
  return 0;
}
