// RUN: %clang_cl -Od %s -Fe%t /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /hotpatch /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /hotpatch /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s

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

void test1_default() {
}

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

const char *test2_default() {
    return "constant string";
}

const char * test2_override() {
    return "override string";
}

void test2() {
    assert(!strcmp(test2_default(), "constant string"));
    assert(!strcmp(test2_override(), "override string"));

    auto test2_old = apply_interception(test2_override, test2_default);

    assert(!strcmp(test2_old(), "constant string"));
    assert(!strcmp(test2_default(), "override string"));
}

int main() {
    test1();
    test2();

// CHECK: Success.
    fputs("Success.", stderr);
    return 0;
}