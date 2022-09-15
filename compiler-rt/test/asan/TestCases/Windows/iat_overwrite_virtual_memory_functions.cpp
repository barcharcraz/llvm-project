// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && not %run %t test1 2>&1 | FileCheck %s --check-prefix=CHECK1
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && not %run %t test2 2>&1 | FileCheck %s --check-prefix=CHECK2
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && not %run %t test3 2>&1 | FileCheck %s --check-prefix=CHECK3
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=ignore %run %t test1 2>&1 | FileCheck %s --check-prefix=CHECK4  --allow-empty
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=ignore %run %t test2 2>&1 | FileCheck %s --check-prefix=CHECK5
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=ignore %run %t test3 2>&1 | FileCheck %s --check-prefix=CHECK6
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=protect %run %t test1 2>&1 | FileCheck %s --check-prefix=CHECK7
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=protect %run %t test2 2>&1 | FileCheck %s --check-prefix=CHECK7
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t /link imagehlp.lib && %env_asan_opts=iat_overwrite=protect %run %t test3 2>&1 | FileCheck %s --check-prefix=CHECK7

#include "iat_overwrite_protection.h"
#ifdef _DEBUG
#define DBG_STR "_dbg"
#else
#define DBG_STR
#endif

#ifdef _M_IX86
#define ARCH_STR "i386"
#elif defined(_M_AMD64)
#define ARCH_STR "x86_64"
#else
#error Unsupported architecture.
#endif

#define ASAN_DLL_NAME "clang_rt.asan" DBG_STR "_dynamic-" ARCH_STR ".dll"

const char *moduleName;

template <typename T, typename... Args>
auto LookupAndCall(const char *name, Args &&...args) {
  HMODULE mod = GetModuleHandleA(moduleName);
  auto fn = reinterpret_cast<T>(GetProcAddress(mod, name));
  if (!fn) {
    std::cerr << "Unable to lookup: " << name << " in module: " << moduleName << std::endl;
    fail();
  }
  return fn(args...);
}

void *__sanitizer_virtual_alloc(
    void *lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
  using fntype = decltype(__sanitizer_virtual_alloc) *;
  return LookupAndCall<fntype>("__sanitizer_virtual_alloc", lpAddress, dwSize, flAllocationType, flProtect);
}
SIZE_T __sanitizer_virtual_query(
    const void *lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
  using fntype = decltype(__sanitizer_virtual_query) *;
  return LookupAndCall<fntype>("__sanitizer_virtual_query", lpAddress, lpBuffer, dwLength);
}
int __sanitizer_virtual_protect(
    void *lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD *lpflOldProtect) {
  using fntype = decltype(__sanitizer_virtual_protect) *;
  return LookupAndCall<fntype>("__sanitizer_virtual_protect", lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID MyVirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD) {
  fail("Called overwritten VirtualAlloc");
  // This error is different than the statically linked version of the test. This is a result
  // of the behavior of the asan memory accessors
  // CHECK4: {{(Called overwritten VirtualAlloc|ERROR: Failed to mmap|^$)}}
}

BOOL MyVirtualProtect(void *, SIZE_T, DWORD, DWORD *) {
  fail("Called overwritten VirtualProtect");
  // CHECK5: Called overwritten VirtualProtect
}

SIZE_T MyVirtualQuery(const void *, PMEMORY_BASIC_INFORMATION, SIZE_T) {
  fail("Called overwritten VirtualQuery");
  // CHECK6: Called overwritten VirtualQuery
}

void VirtualAllocTest(const char *module) {
  OverwriteIATOrFail(module, "kernel32.dll", "VirtualAlloc", &MyVirtualAlloc, __sanitizer_virtual_protect);
  __sanitizer_virtual_alloc(0, 128, MEM_RESERVE,
                            PAGE_NOACCESS);
  // CHECK1: ERROR: IAT overwrite detected: VirtualAlloc IAT entry overwritten.
}

void VirtualProtectTest(const char *module) {
  OverwriteIATOrFail(module, "kernel32.dll", "VirtualProtect", &MyVirtualProtect, __sanitizer_virtual_protect);
  DWORD old_protection;
  __sanitizer_virtual_protect(nullptr, 0, PAGE_NOACCESS,
                              &old_protection);
  // CHECK2: ERROR: IAT overwrite detected: VirtualProtect IAT entry overwritten.
}

void VirtualQueryTest(const char *module) {
  OverwriteIATOrFail(module, "kernel32.dll", "VirtualQuery", &MyVirtualQuery, __sanitizer_virtual_protect);
  MEMORY_BASIC_INFORMATION mbi;
  __sanitizer_virtual_query(&mbi, &mbi,
                            sizeof(mbi));
  // CHECK3: ERROR: IAT overwrite detected: VirtualQuery IAT entry overwritten.
}

int main(int argc, char **argv) {
#ifndef _DLL
  moduleName = argv[0];
#else
  moduleName = ASAN_DLL_NAME;
#endif
  if (argc != 2) {
    return 1;
  }
  if (!strcmp(argv[1], "test1")) {
    VirtualAllocTest(moduleName);
  }
  if (!strcmp(argv[1], "test2")) {
    VirtualProtectTest(moduleName);
  }
  if (!strcmp(argv[1], "test3")) {
    VirtualQueryTest(moduleName);
  }

  std::cerr << "Success." << std::endl;
  // CHECK7: Success.
  return 0;
}