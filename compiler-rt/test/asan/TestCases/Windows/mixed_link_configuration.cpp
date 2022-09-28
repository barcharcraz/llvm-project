// Build all DLLs
// RUN: %clang_asan_no_rt -Od /MT  /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.asan.mt.dll
// RUN: %clang_asan_no_rt -Od /MD  /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.asan.md.dll
// RUN: %clang_asan_no_rt -Od /MTd /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.asan.mtd.dll
// RUN: %clang_asan_no_rt -Od /MDd /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.asan.mdd.dll
// RUN: %clang_cl_no_rt   -Od /MT  /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.mt.dll
// RUN: %clang_cl_no_rt   -Od /MD  /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.md.dll
// RUN: %clang_cl_no_rt   -Od /MTd /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.mtd.dll
// RUN: %clang_cl_no_rt   -Od /MDd /LD %p/mixed_link_configuration_dll.cpp -Femixed_link_configuration_dll.mdd.dll

// All ASAN /MT scenarios
// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// RUN: echo "ASAN /MT EXE -> ASAN /MT DLL: %t.asan.mt.to.asan.mt.exe" 1>&2 && %run %t.asan.mt.to.asan.mt.exe 2>&1 | FileCheck %s

// Unsupported on X86 since two instances and shadow map overlaps
// RUN: %if_not_i386 ( %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib )
// RUN: %if_not_i386 ( echo "ASAN /MT EXE -> ASAN /MD DLL: %t.asan.mt.to.asan.md.exe" 1>&2 && %run %t.asan.mt.to.asan.md.exe 2>&1 | FileCheck %s )
// RUN: %if_i386     ( echo "ASAN /MT EXE -> ASAN /MD DLL: Disabled" )

// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// RUN: echo "ASAN /MT EXE -> ASAN /MTd DLL: %t.asan.mt.to.asan.mtd.exe" 1>&2 && %run %t.asan.mt.to.asan.mtd.exe 2>&1 | FileCheck %s

// Unsupported on X86 since two instances and shadow map overlaps
// RUN: %if_not_i386 ( %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib )
// RUN: %if_not_i386 ( echo "ASAN /MT EXE -> ASAN /MDd DLL: %t.asan.mt.to.asan.mdd.exe" 1>&2 && %run %t.asan.mt.to.asan.mdd.exe 2>&1 | FileCheck %s )
// RUN: %if_i386     ( echo "ASAN /MT EXE -> ASAN /MDd DLL: Disabled" )

// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.mt.exe mixed_link_configuration_dll.mt.lib
// RUN: echo "ASAN /MT EXE -> non-ASAN /MT DLL: %t.asan.mt.to.mt.exe" 1>&2 && %run %t.asan.mt.to.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.md.exe mixed_link_configuration_dll.md.lib
// RUN: echo "ASAN /MT EXE -> non-ASAN /MD DLL: %t.asan.mt.to.md.exe" 1>&2 && %run %t.asan.mt.to.md.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.mtd.exe mixed_link_configuration_dll.mtd.lib
// RUN: echo "ASAN /MT EXE -> non-ASAN /MTd DLL: %t.asan.mt.to.mtd.exe" 1>&2 && %run %t.asan.mt.to.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MT %s -Fe%t.asan.mt.to.mdd.exe mixed_link_configuration_dll.mdd.lib
// RUN: echo "ASAN /MT EXE -> non-ASAN /MDd DLL: %t.asan.mt.to.mdd.exe" 1>&2 && %run %t.asan.mt.to.mdd.exe 2>&1 | FileCheck %s


// All ASAN /MD scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "ASAN /MD EXE -> ASAN /MT DLL: %t.asan.md.to.asan.mt.exe" 1>&2 && %run %t.asan.md.to.asan.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// RUN: echo "ASAN /MD EXE -> ASAN /MD DLL: %t.asan.md.to.asan.md.exe" 1>&2 && %run %t.asan.md.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "ASAN /MD EXE -> ASAN /MTd DLL: %t.asan.md.to.asan.mtd.exe" 1>&2 && %run %t.asan.md.to.asan.mtd.exe 2>&1 | FileCheck %s

// Unsupported because two ASAN instances (manifests as wild pointer freed during startup)
// SKIP: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// SKIP: echo "ASAN /MD EXE -> ASAN /MDd DLL: %t.asan.md.to.asan.mdd.exe" 1>&2 && %run %t.asan.md.to.asan.mdd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.mt.exe mixed_link_configuration_dll.mt.lib
// RUN: echo "ASAN /MD EXE -> non-ASAN /MT DLL: %t.asan.md.to.mt.exe" 1>&2 && %run %t.asan.md.to.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.md.exe mixed_link_configuration_dll.md.lib
// RUN: echo "ASAN /MD EXE -> non-ASAN /MD DLL: %t.asan.md.to.md.exe" 1>&2 && %run %t.asan.md.to.md.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.mtd.exe mixed_link_configuration_dll.mtd.lib
// RUN: echo "ASAN /MD EXE -> non-ASAN /MTd DLL: %t.asan.md.to.mtd.exe" 1>&2 && %run %t.asan.md.to.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MD %s -Fe%t.asan.md.to.mdd.exe mixed_link_configuration_dll.mdd.lib
// RUN: echo "ASAN /MD EXE -> non-ASAN /MDd DLL: %t.asan.md.to.mdd.exe" 1>&2 && %run %t.asan.md.to.mdd.exe 2>&1 | FileCheck %s


// All ASAN /MTd scenarios
// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// RUN: echo "ASAN /MTd EXE -> ASAN /MT DLL: %t.asan.mt.to.asan.mt.exe" 1>&2 && %run %t.asan.mt.to.asan.mt.exe 2>&1 | FileCheck %s

// Unsupported on X86 since two instances and shadow map overlaps
// RUN: %if_not_i386 ( %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib )
// RUN: %if_not_i386 ( echo "ASAN /MTd EXE -> ASAN /MD DLL: %t.asan.mt.to.asan.md.exe" 1>&2 && %run %t.asan.mt.to.asan.md.exe 2>&1 | FileCheck %s )
// RUN: %if_i386     ( echo "ASAN /MTd EXE -> ASAN /MD DLL: Disabled" )

// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// RUN: echo "ASAN /MTd EXE -> ASAN /MTd DLL: %t.asan.mt.to.asan.mtd.exe" 1>&2 && %run %t.asan.mt.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %if_not_i386 ( %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib )
// RUN: %if_not_i386 ( echo "ASAN /MTd EXE -> ASAN /MDd DLL: %t.asan.mt.to.asan.mdd.exe" 1>&2 && %run %t.asan.mt.to.asan.mdd.exe 2>&1 | FileCheck %s )
// RUN: %if_i386     ( echo "ASAN /MTd EXE -> ASAN /MDd DLL: Disabled" )

// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.mt.exe mixed_link_configuration_dll.mt.lib
// RUN: echo "ASAN /MTd EXE -> non-ASAN /MT DLL: %t.asan.mt.to.mt.exe" 1>&2 && %run %t.asan.mt.to.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.md.exe mixed_link_configuration_dll.md.lib
// RUN: echo "ASAN /MTd EXE -> non-ASAN /MD DLL: %t.asan.mt.to.md.exe" 1>&2 && %run %t.asan.mt.to.md.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.mtd.exe mixed_link_configuration_dll.mtd.lib
// RUN: echo "ASAN /MTd EXE -> non-ASAN /MTd DLL: %t.asan.mt.to.mtd.exe" 1>&2 && %run %t.asan.mt.to.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MTd %s -Fe%t.asan.mt.to.mdd.exe mixed_link_configuration_dll.mdd.lib
// RUN: echo "ASAN /MTd EXE -> non-ASAN /MDd DLL: %t.asan.mt.to.mdd.exe" 1>&2 && %run %t.asan.mt.to.mdd.exe 2>&1 | FileCheck %s


// All ASAN /MDd scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "ASAN /MDd EXE -> ASAN /MT DLL: %t.asan.md.to.asan.mt.exe" 1>&2 && %run %t.asan.md.to.asan.mt.exe 2>&1 | FileCheck %s

// Unsupported because two ASAN instances (manifests as wild pointer freed during startup)
// SKIP: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// SKIP: echo "ASAN /MDd EXE -> ASAN /MD DLL: %t.asan.md.to.asan.md.exe" 1>&2 && %run %t.asan.md.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "ASAN /MDd EXE -> ASAN /MTd DLL: %t.asan.md.to.asan.mtd.exe" 1>&2 && %run %t.asan.md.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// RUN: echo "ASAN /MDd EXE -> ASAN /MDd DLL: %t.asan.md.to.asan.mdd.exe" 1>&2 && %run %t.asan.md.to.asan.mdd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.mt.exe mixed_link_configuration_dll.mt.lib
// RUN: echo "ASAN /MDd EXE -> non-ASAN /MT DLL: %t.asan.md.to.mt.exe" 1>&2 && %run %t.asan.md.to.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.md.exe mixed_link_configuration_dll.md.lib
// RUN: echo "ASAN /MDd EXE -> non-ASAN /MD DLL: %t.asan.md.to.md.exe" 1>&2 && %run %t.asan.md.to.md.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.mtd.exe mixed_link_configuration_dll.mtd.lib
// RUN: echo "ASAN /MDd EXE -> non-ASAN /MTd DLL: %t.asan.md.to.mtd.exe" 1>&2 && %run %t.asan.md.to.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_asan_no_rt -Od /MDd %s -Fe%t.asan.md.to.mdd.exe mixed_link_configuration_dll.mdd.lib
// RUN: echo "ASAN /MDd EXE -> non-ASAN /MDd DLL: %t.asan.md.to.mdd.exe" 1>&2 && %run %t.asan.md.to.mdd.exe 2>&1 | FileCheck %s


// All non-ASAN /MT scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MT %s -Fe%t.mt.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "non-ASAN /MT EXE -> ASAN /MT DLL: %t.mt.to.asan.mt.exe" 1>&2 && %run %t.mt.to.asan.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MT %s -Fe%t.mt.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// RUN: echo "non-ASAN /MT EXE -> ASAN /MD DLL: %t.mt.to.asan.md.exe" 1>&2 && %run %t.mt.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MT %s -Fe%t.mt.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "non-ASAN /MT EXE -> ASAN /MTd DLL: %t.mt.to.asan.mtd.exe" 1>&2 && %run %t.mt.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MT %s -Fe%t.mt.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// RUN: echo "non-ASAN /MT EXE -> ASAN /MDd DLL: %t.mt.to.asan.mdd.exe" 1>&2 && %run %t.mt.to.asan.mdd.exe 2>&1 | FileCheck %s


// All non-ASAN /MD scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MD %s -Fe%t.md.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "non-ASAN /MD EXE -> ASAN /MT DLL: %t.md.to.asan.mt.exe" 1>&2 && %run %t.md.to.asan.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MD %s -Fe%t.md.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// RUN: echo "non-ASAN /MD EXE -> ASAN /MD DLL: %t.md.to.asan.md.exe" 1>&2 && %run %t.md.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MD %s -Fe%t.md.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "non-ASAN /MD EXE -> ASAN /MTd DLL: %t.md.to.asan.mtd.exe" 1>&2 && %run %t.md.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MD %s -Fe%t.md.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// RUN: echo "non-ASAN /MD EXE -> ASAN /MDd DLL: %t.md.to.asan.mdd.exe" 1>&2 && %run %t.md.to.asan.mdd.exe 2>&1 | FileCheck %s


// All non-ASAN /MTd scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MTd %s -Fe%t.mt.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "non-ASAN /MTd EXE -> ASAN /MT DLL: %t.mt.to.asan.mt.exe" 1>&2 && %run %t.mt.to.asan.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MTd %s -Fe%t.mt.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// RUN: echo "non-ASAN /MTd EXE -> ASAN /MD DLL: %t.mt.to.asan.md.exe" 1>&2 && %run %t.mt.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MTd %s -Fe%t.mt.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "non-ASAN /MTd EXE -> ASAN /MTd DLL: %t.mt.to.asan.mtd.exe" 1>&2 && %run %t.mt.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MTd %s -Fe%t.mt.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// RUN: echo "non-ASAN /MTd EXE -> ASAN /MDd DLL: %t.mt.to.asan.mdd.exe" 1>&2 && %run %t.mt.to.asan.mdd.exe 2>&1 | FileCheck %s


// All non-ASAN /MDd scenarios
// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MDd %s -Fe%t.md.to.asan.mt.exe mixed_link_configuration_dll.asan.mt.lib
// SKIP: echo "non-ASAN /MDd EXE -> ASAN /MT DLL: %t.md.to.asan.mt.exe" 1>&2 && %run %t.md.to.asan.mt.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MDd %s -Fe%t.md.to.asan.md.exe mixed_link_configuration_dll.asan.md.lib
// RUN: echo "non-ASAN /MDd EXE -> ASAN /MD DLL: %t.md.to.asan.md.exe" 1>&2 && %run %t.md.to.asan.md.exe 2>&1 | FileCheck %s

// Unsupported because EXE is does not contain ASAN
// SKIP: %clang_cl_no_rt -Od /MDd %s -Fe%t.md.to.asan.mtd.exe mixed_link_configuration_dll.asan.mtd.lib
// SKIP: echo "non-ASAN /MDd EXE -> ASAN /MTd DLL: %t.md.to.asan.mtd.exe" 1>&2 && %run %t.md.to.asan.mtd.exe 2>&1 | FileCheck %s

// RUN: %clang_cl_no_rt -Od /MDd %s -Fe%t.md.to.asan.mdd.exe mixed_link_configuration_dll.asan.mdd.lib
// RUN: echo "non-ASAN /MDd EXE -> ASAN /MDd DLL: %t.md.to.asan.mdd.exe" 1>&2 && %run %t.md.to.asan.mdd.exe 2>&1 | FileCheck %s


// Only test during /MD builds to save time, since test is independent of runtime flavor.
// REQUIRES: asan-release-runtime, asan-dynamic-runtime

#include <malloc.h>
#include <stdio.h>

#ifdef __SANITIZE_ADDRESS__
#define ASAN_CONFIG "ASAN"
#else
#define ASAN_CONFIG "non-ASAN"
#endif

#ifdef _DLL
#define LINK_CONFIG "D"
#else
#define LINK_CONFIG "T"
#endif

#ifdef _DEBUG
#define DBG_CONFIG "d"
#else
#define DBG_CONFIG
#endif

struct CallFromExe {
    static void *malloc(size_t sz) {
        return ::malloc(sz);
    }

    static size_t msize(void *ptr) {
        return ::_msize(ptr);
    }

    static void free(void *ptr) {
        ::free(ptr);
    }
};

static const char *exe_description() {
    return ASAN_CONFIG " /M" LINK_CONFIG DBG_CONFIG " EXE";
}

extern "C" __declspec(dllimport) const char *dll_description();

extern "C" __declspec(dllimport) void *malloc_via_dll(size_t);

extern "C" __declspec(dllimport) size_t msize_via_dll(void *);

extern "C" __declspec(dllimport) void free_via_dll(void *);

struct CallFromDll {
    static void *malloc(size_t sz) {
        return ::malloc(sz);
    }

    static size_t msize(void *ptr) {
        return ::_msize(ptr);
    }

    static void free(void *ptr) {
        ::free(ptr);
    }
};

template <typename Module>
void malloc_test() {
    void * ptr = Module::malloc(32);
    fprintf(stderr, "Allocated 0x%p\n", ptr);

    fprintf(stderr, "Size of 0x%p is %zd\n", ptr, Module::msize(ptr));

    Module::free(ptr);
    fprintf(stderr, "Freed 0x%p\n", ptr);
}

int main() {
    fprintf(stderr, "Testing '%s' with '%s'\n", exe_description(), dll_description());

    malloc_test<CallFromExe>();
    malloc_test<CallFromDll>();

    fputs("Success", stderr);
// CHECK: Allocated [[EXEADDR:0x[0-9A-F]+]]
// CHECK: Size of [[EXEADDR]] is 32
// CHECK: Freed [[EXEADDR]]
// CHECK: Allocated [[DLLADDR:0x[0-9A-F]+]]
// CHECK: Size of [[DLLADDR]] is 32
// CHECK: Freed [[DLLADDR]]
// CHECK: Success
}