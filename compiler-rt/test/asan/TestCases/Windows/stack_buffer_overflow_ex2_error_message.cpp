// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 9 2>&1 | FileCheck %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-stack-buffer-overflow
int main(int argc, char **argv) {
    assert(argc >= 2);
    int idx = atoi(argv[1]);
    char AAA[10], BBB[10], CCC[10];
    memset(AAA, 0, sizeof(AAA));
    memset(BBB, 0, sizeof(BBB));
    memset(CCC, 0, sizeof(CCC));
    int res = 0;
    char *p = AAA + idx;
    printf("AAA: %p\ny: %p\nz: %p\np: %p\n", AAA, BBB, CCC, p);

    return *(short*)(p) + BBB[argc % 2] + CCC[argc % 2];  // Boom! ... when argument is 9
  // CHECK:ERROR: AddressSanitizer: stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]] at pc {{0x[0-9a-f]+}} bp {{0x[0-9a-f]+}} sp {{0x[0-9a-f]+}}
  // CHECK: READ of size {{[0-9]+}} at [[ADDR]] thread T0
  // CHECK: Address [[ADDR]] is located in stack of thread T0 at offset {{[0-9]+}} in frame
  // CHECK: This frame has {{[0-9]+}} object(s):
  // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'AAA' <== Memory access at offset {{[0-9]+}} partially overflows this variable
  // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'BBB'
  // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'CCC'
  // CHECK: HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
  // CHECK: (longjmp, SEH and C++ exceptions *are* supported)
  // CHECK: SUMMARY: AddressSanitizer: stack-buffer-overflow
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