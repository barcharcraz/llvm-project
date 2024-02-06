// ntdll has a bug where strtol does not set errno. 
// This test is a sanity check that we correctly intercept ntdll and therefore that the bug *does* replicate.
// RUN: %clangxx_asan %s -o %t && %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <string>
#include <windows.h>

int main()
{
    typedef long (*strtol_type)(const char *nptr, char **endptr, int base);

    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (!ntdll) {
      puts("Couldn't load ntdll.dll!!");
      return -1;
    }

    strtol_type strtol_ptr = (strtol_type)GetProcAddress(ntdll, "strtol");

    errno = 0;
    const auto val = strtol_ptr("3500000000000000000000000000000", nullptr, 10);
    if (errno != 0) // should be ERANGE, but ntdll.dll has a bug
    {
      puts("ntdll.dll failed");
      return 1;
    }

    puts("Done.\n");
    return 0;
}

// CHECK-NOT: ERROR: AddressSanitizer
// CHECK: Done.
