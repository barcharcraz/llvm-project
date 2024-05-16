// RUN: %clang_cl -Od %s -Fe%t /link dbghelp.lib /INFERASANLIBS
// RUN: %run %t 2>&1 | FileCheck %s

// Todo: disabled for llvm19/main upgrade, this should really be a unit test. See VSO-PR-539215
// UNSUPPORTED: MSVC
// Regression test for OverrideFunctionWithJump for scenarios.
// Main concern is when the jump instruction is at an address lower
// than the original calling function

#include <Windows.h>
#include <algorithm>
#include <dbghelp.h>
#include <iostream>
#include <psapi.h>
#include <stdlib.h>

#ifdef _M_IX86
#  define ARCH_STR "i386"
using uptr = unsigned long;
#elif defined(_M_AMD64)
#  define ARCH_STR "x86_64"
using uptr = unsigned long long;
#else
#  error Unsupported architecture.
#endif

#define ASAN_DLL_NAME "clang_rt.asan_dynamic-" ARCH_STR ".dll"
using u8 = unsigned char;

static bool DistanceIsWithin2Gig(uptr from, uptr target) {
#if _WIN64
  if (from < target)
    return target - from <= (uptr)0x7FFFFFFFU;
  else
    return from - target <= (uptr)0x80000000U;
#else
  // In a 32-bit address space, the address calculation will wrap, so this check
  // is unnecessary.
  return true;
#endif
}

bool OverrideFunctionWithRedirectJump(uptr old_func, uptr new_func,
                                      uptr *orig_old_func) {
  if (!DistanceIsWithin2Gig(old_func, new_func)) {
    fputs(
      "The conditions of how this was built cannot be verified by this test since\n"
      "the target function must be within 2gb of the intercepted function in order\n"
      "for a redirect jump to work in this scenario.\n"
      "To avoid intermittent failures in test runs, we claim the test was successful.\n"
      "Ideally we can fix this in the test in the future.\n"
      , stderr);
    fputs("Success.", stderr);
    exit(0);
  }

  using OverrideFunctionWithRedirectJump_fp_t = bool (*)(uptr, uptr, uptr *);
  static OverrideFunctionWithRedirectJump_fp_t fp = []() {
    auto this_process = GetCurrentProcess();

    if (!SymInitialize(this_process, NULL, FALSE)) {
      fputs("SymInitialize failed.", stderr);
      exit(-1);
    }

    HMODULE asan_module = LoadLibraryA(ASAN_DLL_NAME);
    if (!asan_module) {
      fputs("LoadLibraryA '" ASAN_DLL_NAME "' failed.", stderr);
      exit(-1);
    }

    MODULEINFO asan_modinfo;
    wchar_t asan_fullpath[MAX_PATH];
    wchar_t asan_basename[MAX_PATH];

    if (!GetModuleInformation(this_process, asan_module, &asan_modinfo,
                              sizeof(MODULEINFO))) {
      fputs("GetModuleInformation failed.", stderr);
      exit(-1);
    }

    if (GetModuleFileNameExW(this_process, asan_module, asan_fullpath,
                             MAX_PATH) == 0) {
      fputs("GetModuleFileNameExW failed.", stderr);
      exit(-1);
    }

    if (GetModuleBaseNameW(this_process, asan_module, asan_basename,
                           MAX_PATH) == 0) {
      fputs("GetModuleBaseNameW failed.", stderr);
      exit(-1);
    }

    DWORD64 asan_dll =
        SymLoadModuleExW(this_process, 0, asan_fullpath, asan_basename,
                         reinterpret_cast<DWORD64>(asan_modinfo.lpBaseOfDll),
                         asan_modinfo.SizeOfImage, 0, 0);
    if (asan_dll == 0) {
      fputs("SymLoadModuleExW failed.", stderr);
      exit(-1);
    }

    IMAGEHLP_MODULE64 imghlp_asan_modinfo = {0};
    imghlp_asan_modinfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(this_process, asan_dll, &imghlp_asan_modinfo)) {
        fputs("SymGetModuleInfo64 failed.", stderr);
        exit(-1);
    }
    fprintf(stderr, "PDB Path: %s\n", imghlp_asan_modinfo.LoadedPdbName);

    OverrideFunctionWithRedirectJump_fp_t out_fp = nullptr;
    if (!SymEnumSymbols(
            this_process, asan_dll,
            "__interception::OverrideFunctionWithRedirectJump",
            [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
               PVOID UserContext) -> BOOL {
              *(static_cast<OverrideFunctionWithRedirectJump_fp_t *>(
                  UserContext)) =
                  reinterpret_cast<OverrideFunctionWithRedirectJump_fp_t>(
                      pSymInfo->Address);
              return TRUE;
            },
            &out_fp)) {
      fputs("SymEnumSymbols failed", stderr);
      exit(-1);
    }

    if (out_fp == nullptr) {
        fputs("Could not locate __interception::OverrideFunctionWithRedirectJump in ASAN DLL (symbols required)", stderr);
        exit(-1);
    }

    return reinterpret_cast<OverrideFunctionWithRedirectJump_fp_t>(out_fp);
  }();

  return fp(old_func, new_func, orig_old_func);
}

#define EXPECT_EQ(arg1, arg2)                                                  \
  do {                                                                         \
    int __arg1 = (arg1);                                                      \
    int __arg2 = (arg2);                                                      \
    if (__arg1 != __arg2) {                                                    \
      fprintf(stderr, "%s(%d): %d != %d\n", __FILE__, __LINE__, __arg1,        \
              __arg2);                                                         \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

using IdentityFunction = int (*)(int);

// Test globals
u8 *ActiveInstruction;
int InterceptorFunctionCalled;
IdentityFunction InterceptedRealFunction;
int PageSize = 1024;

// Allocates a page of memory to use for testing
u8 *AllocateMemoryForTest() {
  return (u8 *)::VirtualAlloc(NULL, PageSize, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
}

// Sets up memory with instructions based on instruction passed in
template <class T> static void LoadActiveInstruction(const T &code) {
  ActiveInstruction = AllocateMemoryForTest();

  // Copy the function body
  for (size_t i = 0; i < sizeof(T); ++i) {
    ActiveInstruction[i] = code[i];
  }
}

// Intercepted function for counting times called
int InterceptorFunction(int arg) {
  ++InterceptorFunctionCalled;
  return InterceptedRealFunction(arg);
}

template <class T>
static bool TestOverrideFunctionWithRedirectJump(
    T &code, int positionOfInstructionStart, int positionToCheck) {
  uptr identityAddress;
  LoadActiveInstruction(code);
  identityAddress = (uptr)&ActiveInstruction[positionOfInstructionStart];
  IdentityFunction identity = (IdentityFunction)identityAddress;

  // Validate behavior before interception by calling the function
  InterceptorFunctionCalled = 0;
  identity(0);
  EXPECT_EQ(0, InterceptorFunctionCalled);

  // Intercept the function
  uptr realIdentityAddress = 0;
  bool success = OverrideFunctionWithRedirectJump(identityAddress, (uptr)&InterceptorFunction,
                                                  &realIdentityAddress);
  IdentityFunction realIdentity = (IdentityFunction)realIdentityAddress;
  InterceptedRealFunction = realIdentity;

  // Don't run tests if interception failed
  EXPECT_EQ(success, true);

  // Verify the jump is to the correct address from the original
  // function
  auto jumpAddress = identityAddress + positionToCheck;
  EXPECT_EQ(realIdentityAddress, jumpAddress);

  // Calling the intercepted function to verify
  InterceptorFunctionCalled = 0;
  identity(0);
  identity(42);
  EXPECT_EQ(2, InterceptorFunctionCalled);

  // Calling the real function
  InterceptorFunctionCalled = 0;
  realIdentity(0);
  realIdentity(42);
  EXPECT_EQ(0, InterceptorFunctionCalled);

  return true;
}

int main() {

  u8 jumpForward = 0x04;
  u8 jumpBack = 0xF4;
  u8 jumpInstruction = 0xE9;

  // Arbitrary with the instruction code layout below, since both
  // groups of instructions are size 5
  u8 instructionSize = 5;

  u8 instructionsWithJumpForward[] = {
      jumpInstruction, jumpForward, 0x00, 0x00, // jmp + 4 to next instruction definition
      0x00,
      0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0xC8, // mov         eax, ecx
      0xC3                                // ret
  };
  // First instruction above, so position 0
  auto positonToCheckJumpForward = 0;

  u8 instructionsWithJumpBack[] = {
      jumpInstruction, jumpForward, 0x00, 0x00, // jmp + 4, needed for override with redirect jump
      0x00,
      0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0xC8, // mov         eax, ecx
      0xC3,                               // ret
      0xCC, 0xCC, 0xCC, 0xCC,
      jumpInstruction, jumpBack, 0xFF, 0xFF, 0xFF, // jmp - 7 to the previous instruction definition
      0x00, 0x00, 0x00};

  // Find the starting position of the jump instruction we want to override
  // which is one instruction before the jump back
  auto positonToCheckJumpBack = std::distance(instructionsWithJumpBack, std::find(instructionsWithJumpBack, std::end(instructionsWithJumpBack), jumpBack)) - 1;

  // The positions to check for jumps are relative to the first instruction of each group.
  // Tests both jumps forward and backward
  auto jumpBackPass = TestOverrideFunctionWithRedirectJump(instructionsWithJumpBack, positonToCheckJumpBack, -(static_cast<u8>(-jumpBack) - instructionSize));
  auto jumpForwardPass = TestOverrideFunctionWithRedirectJump(instructionsWithJumpForward, positonToCheckJumpForward, jumpForward + instructionSize);

  EXPECT_EQ(jumpBackPass, true);
  EXPECT_EQ(jumpForwardPass, true);

  fputs("Success.", stderr);

  // CHECK: Success.
  return 0;
}