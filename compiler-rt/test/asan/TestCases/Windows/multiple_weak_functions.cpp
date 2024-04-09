// RUN: %clang_cl_asan -Od /LD %s -Fe%t_dll.dll -DBUILD_DLL
// RUN: %clang_cl_asan -Od %s -Fe%t %t_dll.lib -DNO_EXE_ON_ERROR
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefix=CHECK2

#ifdef BUILD_DLL
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllimport)
#endif

#include <stdio.h>
#include <stdlib.h>
extern "C" DLLEXPORT int *allocate_int();

#ifdef BUILD_DLL

extern "C" void __asan_on_error() {
    fputs("__asan_on_error registered by DLL\n", stderr);
}

int *allocate_int() {
    return static_cast<int *>(malloc(4));
}

#else

#ifndef NO_EXE_ON_ERROR
extern "C" void __asan_on_error() {
    fputs("__asan_on_error registered by EXE\n", stderr);
}
#endif


int main() {
    allocate_int()[-1] = 5;
    return 0;
}

#endif

// CHECK: __asan_on_error registered by EXE
// CHECK: AddressSanitizer: heap-buffer-overflow

// CHECK2: __asan_on_error registered by DLL
// CHECK2: AddressSanitizer: heap-buffer-overflow
