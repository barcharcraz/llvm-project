// RUN: %clang_cl -Od %s -Fe%t /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /hotpatch /link /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl -Od %s -Fe%t /hotpatch /link /INFERASANLIBS:DEBUG
// RUN: %run %t 2>&1 | FileCheck %s

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" __declspec(dllimport)
bool __cdecl __sanitizer_register_weak_function(
    const char *export_name,
    void *user_function,
    void **old_function = nullptr
    );

// Not actually calling these, just making sure the interception doesn't explode.
void empty_implementation() {
}

void check_interception(const char *export_name) {
    // Specifically not checking this works when saving the function, since
    // that is not what happens during weak function registration.
    if (!__sanitizer_register_weak_function(export_name, &empty_implementation)) {
        fprintf(stderr, "Unable to register weak function for '%s'\n", export_name);
        exit(1);
    }
}

int main() {
    check_interception("__sanitizer_on_print__dll");
    check_interception("__sanitizer_report_error_summary__dll");
    check_interception("__sanitizer_sandbox_on_notify__dll");

    check_interception("__sanitizer_weak_hook_memcmp__dll");
    check_interception("__sanitizer_weak_hook_strcmp__dll");
    check_interception("__sanitizer_weak_hook_strncmp__dll");
    check_interception("__sanitizer_weak_hook_strstr__dll");

    check_interception("__sanitizer_free_hook__dll");
    check_interception("__sanitizer_malloc_hook__dll");

    check_interception("__sancov_default_options__dll");
    check_interception("__sanitizer_cov_trace_cmp__dll");
    check_interception("__sanitizer_cov_trace_cmp2__dll");
    check_interception("__sanitizer_cov_trace_cmp4__dll");
    check_interception("__sanitizer_cov_trace_cmp8__dll");
    check_interception("__sanitizer_cov_trace_const_cmp1__dll");
    check_interception("__sanitizer_cov_trace_const_cmp2__dll");
    check_interception("__sanitizer_cov_trace_const_cmp4__dll");
    check_interception("__sanitizer_cov_trace_const_cmp8__dll");
    check_interception("__sanitizer_cov_trace_div4__dll");
    check_interception("__sanitizer_cov_trace_div8__dll");
    check_interception("__sanitizer_cov_trace_gep__dll");
    check_interception("__sanitizer_cov_trace_pc_guard__dll");
    check_interception("__sanitizer_cov_trace_pc_guard_init__dll");
    check_interception("__sanitizer_cov_trace_pc_indir__dll");
    check_interception("__sanitizer_cov_trace_switch__dll");
    check_interception("__sanitizer_cov_8bit_counters_init__dll");
    check_interception("__sanitizer_cov_bool_flag_init__dll");
    check_interception("__sanitizer_cov_pcs_init__dll");

    // Checked by default_options.cpp - this will be used even without /fsanitize=address.
    //check_interception("__asan_default_options__dll");

    check_interception("__asan_default_suppressions__dll");
    check_interception("__asan_on_error__dll");

    // CHECK: Success.
    fputs("Success.", stderr);
    return 0;

}