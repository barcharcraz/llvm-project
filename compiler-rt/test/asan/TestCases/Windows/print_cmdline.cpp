// Check that ASan can print reproducer cmdline for failed binary if desired.
//
// RUN: %clang_cl_asan /Od -o %t %s
//
// RUN: env not %run %t 2>&1 | FileCheck %s
// RUN: %env_asan_opts=print_cmdline=false not %run %t 2>&1 | FileCheck %s
// RUN: %env_asan_opts=print_cmdline=true not %run %t first second/third 2>&1 | FileCheck %s --check-prefix CHECK-PRINT
// RUN: %env_asan_opts=print_cmdline=true:continue_on_error=1 %run %t first second/third 2>&1 | FileCheck %s --check-prefix CHECK-PRINT
// RUN: %env_asan_opts=print_cmdline=true not %run %t 2>&1 | FileCheck %s --check-prefix CHECK-EMPTY-PRINT

// See: TestCases\Posix\print_cmdline.cpp

volatile int ten = 10;

int main() {
  char x[10];
  // CHECK-NOT: Command:
  // CHECK-PRINT: {{Command: .*print_cmdline.cpp.tmp first second/third}}
  // CHECK-EMPTY-PRINT: {{Command: .*print_cmdline.cpp.tmp}}
  x[ten] = 1; // BOOM
  return 0;
}