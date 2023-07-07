// RUN: ml64.exe /c /Fo%t_asm.obj %p/intercept_small_func_amd64.asm
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /hotpatch /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /hotpatch /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-32-bits

// Testing small functions like this is necessary now that we register weak functions
// by intercepting functions inside ASAN and replacing them with user-provided ones.
// The default implementations of the weak functions are typically very small and simple,
// like the examples in this test.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" __declspec(dllimport)
bool __cdecl __sanitizer_override_function_by_addr(
    void *source_function,
    void *target_function,
    void **old_target_function = nullptr
    );

template <typename F>
F *apply_interception(const F& source, const F& target) {
    void *old_default = nullptr;
    if (!__sanitizer_override_function_by_addr(&source, &target, &old_default)) {
        fputs("__sanitizer_override_function_by_addr failed.", stderr);
        exit(1);
    }
    return reinterpret_cast<F*>(old_default);
}

extern "C" void test1_default();

int test1_var = 0;
void test1_override() {
    ++test1_var;
}

void test1() {
    test1_default();
    assert(test1_var == 0);

    auto test1_old = apply_interception(test1_override, test1_default);

    test1_old();
    assert(test1_var == 0);

    test1_override();
    assert(test1_var == 1);
}

int main() {
    test1();

// CHECK: Success.
    fputs("Success.", stderr);
    return 0;
}