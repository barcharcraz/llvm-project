// RUN: %clang_cl_asan /Od %s -Fe%t /link /force:multiple
// RUN: not %run %t
// RUN: env ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1 %run %t
// UNSUPPORTED: asan-64-bits, asan-dynamic-runtime

/* Written to verify that running this with the 'continue on interception error'
 *  variable is working correctly. There is also a warning message dumped into
 *  the debugger, if it is present. Writing the test for this would depend on
 *  windbg, cdb, or VS to actually pull the warning message, so we'll skip
 *  forcing that on everyone.
 */

// Create a definition of strchr that is only weird instructions that aren't in
// interception_win.cpp
extern "C" char* strchr(char* a) {
    __asm {
        xchg edx,esp;
        mov ebp,ecx;
        xor ebp,ebp;
    }
    return 0;
}

/* Do nothing. All that needs to happen is the function to be present. When run
 * under a debugger it will throw an warning to the user that a function was not
 * properly intercepted.
 */
int main() {
    return 0;
}