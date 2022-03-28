// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <Windows.h>

int ExternalAlign = 5;

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-invalid-allocation-alignment
int main(){
    // this externally calculated alignment of 5 is not valid.
    void* ptr = _aligned_malloc(8,ExternalAlign); 
    // CHECK: ERROR: AddressSanitizer: invalid allocation alignment: 5, alignment must be a power of two (thread T0)
    // CHECK: HINT: if you don't care about these errors you may set allocator_may_return_null=1
    // CHECK: SUMMARY: AddressSanitizer: invalid-allocation-alignment
    return (ptr == nullptr && errno == EINVAL) ? 0 : -1;
}