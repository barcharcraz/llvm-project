// RUN: %ml /c /Fo%t_asm.obj %p/interception_failed_msg.asm
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-1
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS:DEBUG
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-1
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS
// RUN: env ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1 not %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-2
// RUN: %clang_cl -Od %s %t_asm.obj -Fe%t /link /INFERASANLIBS:DEBUG
// RUN: env ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1 not %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-2

extern "C" __declspec(dllimport)
bool __cdecl __sanitizer_override_function_by_addr(
    void *source_function,
    void *target_function,
    void **old_target_function = nullptr
    );

#ifdef _M_AMD64
extern "C" void cannot_be_intercepted();
#else
extern "C" void cannot_be_intercepted() {
    __asm {
        xchg edx,esp;
        mov ebp,ecx;
        xor ebp,ebp;
    }
}
#endif

void override_func() {
}

int main() {
    void *old = nullptr;
    __sanitizer_override_function_by_addr(&override_func, &cannot_be_intercepted, &old);
    // CHECK-1: AddressSanitizer: CHECK failed:{{.*}}Interception failure, stopping early. Set ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1 to try to continue.
    // CHECK-2: Failed to override function at '0x{{[0-9a-f]+}}' with function at '0x{{[0-9a-f]+}}'
    // CHECK-2: AddressSanitizer: CHECK failed:{{.*}}Failed to apply function override.
    return 0;
}
