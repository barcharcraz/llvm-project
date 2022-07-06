// RUN: %clang_cl -Od %s -Fe%t -I%s\..\..\..\..\..\lib\ /link /WHOLEARCHIVE:%asan_lib
// RUN: not %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-dynamic-runtime

// Only use static runtime for linking with test

// Regression test for OverrideFunctionWithJump for scenarios.
// Main concern is when the jump instruction is at an address lower
// than the original calling function

#include "interception\interception.h"
#include <algorithm>
#include <iostream>
#include <windows.h>

using namespace __interception;

#define EXPECT_EQ(arg1, arg2)                                                        \
  do {                                                                               \
    auto __arg1 = (arg1);                                                            \
    auto __arg2 = (arg2);                                                            \
    if (__arg1 != __arg2) {                                                          \
      fprintf(stderr, "%s(%d): %d != %d\n", __FILE__, __LINE__, __arg1, __arg2); \
      exit(1);                                                                       \
    }                                                                                \
  } while (0)

using IdentityFunction = int(*)(int);

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
template <class T>
static void LoadActiveInstruction(const T &code) {
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

  fputs("Success.\n", stderr);

  // CHECK: Success.
  return 0;
}