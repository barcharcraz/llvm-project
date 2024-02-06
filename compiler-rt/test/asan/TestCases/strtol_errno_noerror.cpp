// Check that strtol does not set errno if there is no error.
// RUN: %clangxx_asan %s -o %t && %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <string>

int main()
{
    errno = 0;
    const auto val = strtol("35", nullptr, 10); // See corresponding testcase `strtol_errno_erange.cpp` which asserts that errno is set for an out-of-range invocation.
    if (errno == 0)
    {
      puts("Done.\n");
      return 0;
    }
    else
    {
      return 1;
    }
}

// CHECK-NOT: ERROR: AddressSanitizer
// CHECK: Done.