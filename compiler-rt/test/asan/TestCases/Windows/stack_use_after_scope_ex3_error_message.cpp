// RUN: %clang_cl_asan %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <stdio.h>

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-stack-use-after-scope
// the documentation uses /O1 to compile the code (and fails without optimization). 
// If /O1 is passed at RUN, sometimes it gets overwritten by /Od and the test fails in some pipelines
#pragma optimize("gsy", on )
struct IntHolder {
  explicit IntHolder(int *val = 0) : val_(val) { }
  ~IntHolder() {
    printf("Value: %d\n", *val_);  // Bom!
    // CHECK:ERROR: AddressSanitizer: stack-use-after-scope on address [[ADDR:0x[0-9a-f]+]] at pc {{0x[0-9a-f]+}} bp {{0x[0-9a-f]+}} sp {{0x[0-9a-f]+}}
    // CHECK: READ of size {{[0-9]+}} at [[ADDR]] thread T0
    // CHECK: Address [[ADDR]] is located in stack of thread T0 at offset {{[0-9]+}} in frame
    // CHECK: This frame has {{[0-9]+}} object(s):
    // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'holder'
    // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'x' <== Memory access at offset {{[0-9]+}} is inside this variable
    // CHECK: HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
    // CHECK: (longjmp, SEH and C++ exceptions *are* supported)
    // CHECK: SUMMARY: AddressSanitizer: stack-use-after-scope
    // CHECK: Shadow bytes around the buggy address:
    // CHECK: Shadow byte legend (one shadow byte represents 8 application bytes):
    // CHECK-NEXT: Addressable:           00
    // CHECK-NEXT: Partially addressable: 01 02 03 04 05 06 07 
    // CHECK-NEXT: Heap left redzone:       fa
    // CHECK-NEXT: Freed heap region:       fd
    // CHECK-NEXT: Stack left redzone:      f1
    // CHECK-NEXT: Stack mid redzone:       f2
    // CHECK-NEXT: Stack right redzone:     f3
    // CHECK-NEXT: Stack after return:      f5
    // CHECK-NEXT: Stack use after scope:   f8
    // CHECK-NEXT: Global redzone:          f9
    // CHECK-NEXT: Global init order:       f6
    // CHECK-NEXT: Poisoned by user:        f7
    // CHECK-NEXT: Container overflow:      fc
    // CHECK-NEXT: Array cookie:            ac
    // CHECK-NEXT: Intra object redzone:    bb
    // CHECK-NEXT: ASan internal:           fe
    // CHECK-NEXT: Left alloca redzone:     ca
    // CHECK-NEXT: Right alloca redzone:    cb
  }
  void set(int *val) { val_ = val; }
  int *get() { return val_; }

  int *val_;
};

int main(int argc, char *argv[]) {
  // It is incorrect to use "x" inside the IntHolder destructor, because the lifetime of "x"
  // ends earlier. Per C++ standard, local lLifetimes end in reverse order of declaration.
  IntHolder holder;
  int x = argc;
  holder.set(&x);
  return 0;
}