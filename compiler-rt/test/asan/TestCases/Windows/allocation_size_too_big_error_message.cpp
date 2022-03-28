// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <malloc.h>
#include <memory.h>

int x = 1000;
int y = 1000;

__declspec(noinline) void bad_function() {

  char* buffer = (char*)malloc(x * y * x * y); //Boom!
// CHECK: AddressSanitizer: requested allocation size {{0x[0-9a-f]+}} ({{0x[0-9a-f]+}} after adjustments for alignment, red zones etc.) exceeds maximum supported size of {{0x[0-9a-f]+}} (thread T0)
// CHECK: HINT: if you don't care about these errors you may set allocator_may_return_null=1
// CHECK: SUMMARY: AddressSanitizer: allocation-size-too-big

  memcpy(buffer, buffer + 8, 8); 
}

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-allocation-size-too-big
int main(int argc, char **argv) {
    bad_function();
    return 0;
}
