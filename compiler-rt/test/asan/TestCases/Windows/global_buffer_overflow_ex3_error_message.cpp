// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t -l 2>&1 | FileCheck %s

// Run 4 different ways with the choice of one of these flags:
//
// -g : Global
// -c : File static
// -f : Function static
// -l : String literal

#include <string.h>

struct C {
  static int array[10];
};

// normal global
int global[10];

// class static
int C::array[10];

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-global-buffer-overflow
int main(int argc, char **argv) {

  int one = argc - 1;

  switch (argv[1][1]) {
  case 'g': return global[one * 11];     //Boom! simple global
  case 'c': return C::array[one * 11];   //Boom! class static
  case 'f':
    static int array[10];
    memset(array, 0, 10);
    return array[one * 11];              //Boom! function static
  case 'l':
    // literal global ptr created by compiler

    const char *str = "0123456789";
    return str[one * 11];                //Boom! .rdata string literal allocated by compiler
    // CHECK:ERROR: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]] at pc {{0x[0-9a-f]+}} bp {{0x[0-9a-f]+}} sp {{0x[0-9a-f]+}}
    // CHECK: READ of size {{[0-9]+}} at [[ADDR]] thread T0
    // CHECK: [[ADDR]] is located {{[0-9]+}} bytes to the right of global variable {{.*}} defined in {{.*}} of size {{[0-9]+}}
    // CHECK: SUMMARY: AddressSanitizer: global-buffer-overflow
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
  return 0;
}
