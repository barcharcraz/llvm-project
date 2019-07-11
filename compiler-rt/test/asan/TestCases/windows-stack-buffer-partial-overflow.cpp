// RUN: %clang_asan /Od %s -o%t && %run %t 1
// RUN: %clang_asan /Od %s -o%t && not %run %t -5
// RUN: %clang_asan /Od %s -o%t && not %run %t 4  2>&1 | FileCheck --check-prefix=CHECK-A  %s
// RUN: %clang_asan /Od %s -o%t && not %run %t -1 2>&1 | FileCheck --check-prefix=CHECK-B  %s
// XFAIL: !msvc-host

#include <windows.h>
int main(int argc, char **argv) {
  BYTE a[5] = {0};
  BYTE b[5] = {0};
  BYTE c[5] = {0};
  return *((short *)(a + atoi(argv[1]))) + b[argc % 2] + c[argc % 2];
}
// CHECK-A: 'a'{{.*}} <== {{.*}}partially overflows this variable
// CHECK-B: 'a'{{.*}} <== {{.*}}partially underflows this variable