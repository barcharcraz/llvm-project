// Without ASan's new/delete overrides, the callstack looks slightly different.
// This testcase matches against this difference. 
// (See testcase `double_operator_delete.cpp` for the version with new/delete overrides)
// REQUIRES: debug-crt

// RUN: %clang_cl_asan -Od %s -Fe%t /link /INFERASANLIBS:NO %nonewdelete_libasan /WHOLEARCHIVE:%asan_thunk
// RUN: not %run %t 2>&1 | FileCheck %s

#include <malloc.h>

int main() {
  int *x = new int[42];
  delete [] x;
  delete [] x;
// CHECK: AddressSanitizer: attempting double-free on [[ADDR:0x[0-9a-f]+]]
// CHECK-NEXT: {{#0 .* _free_dbg}}
// CHECK-NEXT: {{#1 .* operator delete}}
// CHECK-NEXT: {{#2 .* operator delete[[]]}}
// CHECK-NEXT: {{#3 .* main .*nonewdelete_callstack_dbg.cpp}}:[[@LINE-5]]
// CHECK: [[ADDR]] is located 0 bytes inside of 168-byte region
// CHECK-LABEL: freed by thread T0 here:
// CHECK-NEXT: {{#0 .* _free_dbg}}
// CHECK-NEXT: {{#1 .* operator delete}}
// CHECK-NEXT: {{#2 .* operator delete[[]]}}
// CHECK-NEXT: {{#3 .* main .*nonewdelete_callstack_dbg.cpp}}:[[@LINE-12]]
// CHECK-LABEL: previously allocated by thread T0 here:
// CHECK-NEXT: {{#0 .* malloc}}
// CHECK-NEXT: {{#1 .* operator new}}
// CHECK-NEXT: {{#2 .* operator new[[]]}}
// CHECK-NEXT: {{#3 .* main .*nonewdelete_callstack_dbg.cpp}}:[[@LINE-18]]
  return 0;
}