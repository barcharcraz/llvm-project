// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <malloc.h>

__declspec(noinline)

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-dynamic-stack-buffer-overflow
void foo(int index, int len) {

    volatile char *str = (volatile char *)_alloca(len);

    //    reinterpret_cast<long>(str) & 31L;

    str[index] = '1'; // Boom !
    // CHECK:ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]] at pc {{0x[0-9a-f]+}} bp {{0x[0-9a-f]+}} sp {{0x[0-9a-f]+}}
    // CHECK: WRITE of size {{[0-9]+}} at [[ADDR]] thread T0
    // CHECK: Address [[ADDR]] is located in stack of thread T0
    // CHECK: SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow
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

int main(int argc, char **argv) {

  foo(33, 10);
  return 0;
}