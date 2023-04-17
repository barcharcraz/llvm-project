// RUN: %clang_cl_asan %s -Fe%t.icf.ref /link /OPT:ICF /OPT:REF -Xclang -fno-builtin-memcpy
// RUN: %clang_cl_asan %s -Fe%t.noicf.ref /link /OPT:NOICF /OPT:REF -Xclang -fno-builtin-memcpy
// RUN: %clang_cl_asan %s -Fe%t.icf.noref /link /OPT:ICF /OPT:NOREF -Xclang -fno-builtin-memcpy
// RUN: %clang_cl_asan %s -Fe%t.noicf.noref /link /OPT:NOICF /OPT:NOREF -Xclang -fno-builtin-memcpy
// RUN: not %run %t.icf.ref 2>&1 | FileCheck %s
// RUN: not %run %t.noicf.ref 2>&1 | FileCheck %s
// RUN: not %run %t.icf.noref 2>&1 | FileCheck %s
// RUN: not %run %t.noicf.noref 2>&1 | FileCheck %s

// RUN: %clang_cl_asan %s -Fe%t_dbg.icf.ref /link /OPT:ICF /OPT:REF /INFERASANLIBS:DEBUG
// RUN: %clang_cl_asan %s -Fe%t_dbg.noicf.ref /link /OPT:NOICF /OPT:REF /INFERASANLIBS:DEBUG
// RUN: %clang_cl_asan %s -Fe%t_dbg.icf.noref /link /OPT:ICF /OPT:NOREF /INFERASANLIBS:DEBUG
// RUN: %clang_cl_asan %s -Fe%t_dbg.noicf.noref /link /OPT:NOICF /OPT:NOREF /INFERASANLIBS:DEBUG
// RUN: not %run %t_dbg.icf.ref 2>&1 | FileCheck %s
// RUN: not %run %t_dbg.noicf.ref 2>&1 | FileCheck %s
// RUN: not %run %t_dbg.icf.noref 2>&1 | FileCheck %s
// RUN: not %run %t_dbg.noicf.noref 2>&1 | FileCheck %s

#include <string.h>

int main() {
  int *buf = new int[4];

  memmove(buf + 1, buf, 3 * sizeof(int));
  memcpy(buf + 1, buf, 3 * sizeof(int));

  delete[] buf;

  memcpy(buf + 1, buf, 3 * sizeof(int));
  // CHECK: AddressSanitizer: heap-use-after-free

  return 0;
}
