// Helper functions to aid with writing ASAN Windows Tests.

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <minmax.h>

[[noreturn]] void check_fail(const char * const expr, const char * const file, const size_t line) {
    // NDEBUG is set in debug to avoid CRT assertion that trigger prior to ASAN report
    // Use CHECK in place of assert.
    fprintf(stderr, "Expression '%s' failed at '%s' on line '%zd'.\n", expr, file, line);
    exit(1);
}

void trace(const char * const expr, const char * const file, const size_t line) {
    // NDEBUG is set in debug to avoid CRT assertion that trigger prior to ASAN report
    // Use CHECK in place of assert.
    fprintf(stderr, "%s[%zd]: %s\n", file, line, expr);
}

#define CHECK(EXPR) do { if (!(EXPR)) { check_fail(#EXPR, __FILE__, __LINE__); } } while (0)
#define TRACE(EXPR) do { trace(#EXPR, __FILE__, __LINE__); (EXPR); } while (0)

inline void print_addr(const char * const name, void * const addr) {
    // Print address in a format similar to ASAN.
    // printf will print %llx by minimizing number of digits,
    // but ASAN Printf will do this but only if not cutting off a byte.
    // Ex: printf 0x%llx  of 1 will print 0x1
    //     ASAN printf %p of 1 will print 0x01
    fprintf(stderr, "%s: ", name);

    const int num_digits = [=]() {
        int num_bytes = 0;
        uintptr_t value = reinterpret_cast<uintptr_t>(addr);
        while (value) {
            value >>= 8;
            ++num_bytes;
        }
        return max(num_bytes * 2, 8);
    }();
    fprintf(stderr, "0x%0*" PRIxPTR "\n", num_digits, reinterpret_cast<uintptr_t>(addr));
}