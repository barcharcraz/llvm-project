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

extern "C" __declspec(dllexport) const char *dll_description() {
    return ASAN_CONFIG " /M" LINK_CONFIG DBG_CONFIG " DLL";
}

extern "C" __declspec(dllexport) void *malloc_via_dll(size_t sz) {
    return malloc(sz);
}

extern "C" __declspec(dllexport) size_t msize_via_dll(void *ptr) {
    return _msize(ptr);
}

extern "C" __declspec(dllexport) void free_via_dll(void *ptr) {
    free(ptr);
}
