// RUN: %clang -Od %s -Fe%t
// RUN: %clang_cl_asan -LD -Od %p/valid_memory_with_asan.cpp -Fe%t.dll
// RUN: %run %t %t.dll
// UNSUPPORTED: clang-static-runtime

#include "Windows.h"
#include "malloc.h"
#include <iostream>
#include <stdio.h>

typedef int *(allocateMemoryFn)();

int *AllocateMemoryFromAnotherDll(const char *dllName) {
  HINSTANCE getProc = LoadLibrary(dllName);
  if (!getProc) {
    throw std::exception("Unable to load dll");
  }
  auto fn = (allocateMemoryFn *)GetProcAddress(getProc, "AllocateMemory");
  if (fn) {
    return (*fn)();
  } else {
    throw std::exception("No function found");
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Must use path to valid_memory_with_asan.dll as argument");
    return 101;
  }
  const char *dllName = argv[1];
  auto pointer = AllocateMemoryFromAnotherDll(dllName);
  pointer = (int *)realloc(pointer, 4);
  return 0;
}