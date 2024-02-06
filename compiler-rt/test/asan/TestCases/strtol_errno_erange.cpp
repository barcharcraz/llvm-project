// Check that strtol properly sets errno
// RUN: %clangxx_asan %s -o %t && %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <string>

int main()
{
    errno = 0;
    const auto val = strtol("3500000000000000000000000000000", nullptr, 10);
    if (errno != ERANGE)
    {
      return 1;
    }
    puts("Done.\n");
    return 0;
}

// CHECK-NOT: ERROR: AddressSanitizer
// CHECK: Done.
