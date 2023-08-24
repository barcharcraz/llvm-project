// RUN: %clang_cl_asan /EHsc /std:c++17 -LD -Od %p/memory_with_asan_dll.cpp -Fe%t.dll
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_NORMAL_MEMORY %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_GLOBAL_FIXED %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_GLOBAL_MOVEABLE %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_LOCAL_FIXED %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_LOCAL_MOVEABLE %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_HEAP_MEMORY %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_ALIGNED_MEMORY %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %clang /EHsc /std:c++17 -Od /DTEST_ALIGNED_OFFSET_MEMORY %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// UNSUPPORTED: clang-static-runtime

#include "memory_operations_after_asan_init.h"

#if TEST_GLOBAL_FIXED
MemoryForManipulating<GlobalFixed> TestMemory;
std::string TestString = "GlobalFixed";
#elif TEST_GLOBAL_MOVEABLE
MemoryForManipulating<GlobalMoveable> TestMemory;
std::string TestString = "GlobalMoveable";
#elif TEST_LOCAL_FIXED
MemoryForManipulating<LocalFixed> TestMemory;
std::string TestString = "LocalFixed";
#elif TEST_LOCAL_MOVEABLE
MemoryForManipulating<LocalMoveable> TestMemory;
std::string TestString = "LocalMoveable";
#elif TEST_HEAP_MEMORY
MemoryForManipulating<HeapMemory> TestMemory;
std::string TestString = "HeapMemory";
#elif TEST_ALIGNED_MEMORY
MemoryForManipulating<AlignedMemory> TestMemory;
std::string TestString = "AlignedMemory";
#elif TEST_ALIGNED_OFFSET_MEMORY
MemoryForManipulating<AlignedOffsetMemory> TestMemory;
std::string TestString = "AlignedOffsetMemory";
#else
MemoryForManipulating<NormalMemory> TestMemory;
std::string TestString = "NormalMemory";
#endif


int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Must use path to memory_with_asan_dll.dll as argument."
              << std::endl;
    //CHECK-NOT: Must use path to memory_with_asan_dll.dll as argument.
    return 101;
  }

  // Allocate prior to asan initialization
  std::cerr << "Memory type: " << TestString << std::endl;
  // CHECK: Memory type: [[TYPE:(GlobalFixed|GlobalMoveable|LocalFixed|LocalMoveable|NormalMemory|AlignedOffsetMemory|AlignedMemory|HeapMemory)]]
  
  AddTests(TestMemory);

  const char *dllName = argv[1];
  HINSTANCE lib = LoadLibrary(dllName);

  // Initialize ASAN
  if (!lib) {
    std::cerr << "Unable to load dll." << std::endl;
    throw std::exception("Unable to load dll");
    //CHECK-NOT: Unable to load dll.
  }

  // Manipulate memory after ASAN is initialized
  TestMemory.AfterASANInit(lib);

  std::cerr << "Success." << std::endl;
  //CHECK: Success.

  // Errors found in memory_operations_after_asan_init.h
  //CHECK-NOT: {{No function found*}}
  //CHECK-NOT: Size Failed.
  //CHECK-NOT: Flags Failed.
  //CHECK-NOT: Realloc Failed.
  //CHECK-NOT: Recalloc Failed.
  return 0;
}