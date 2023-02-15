// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: %run %t 2>&1 | FileCheck %s
#include <stdio.h>
#include <windows.h>
#include "../defines.h"
#include "globallocal_shared.h"

int main() {
  char *buffer;
  buffer = (char*)ALLOC(FixedType, 32),
  buffer[0] = 'a';
  FREE(buffer);
  puts("Okay");
// CHECK: Okay
}
