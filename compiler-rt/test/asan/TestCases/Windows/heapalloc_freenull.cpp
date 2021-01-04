// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1

#include <cassert>
#include <windows.h>

int main() {
  void *allocation = HeapAlloc(GetProcessHeap(), 0, 10);
  assert(allocation != 0);
  HeapFree(GetProcessHeap(), 0, (void *)0);
//TODO: This should actually trigger a report, since Free(NULL) is undefined for windows.
  return 0;
}
