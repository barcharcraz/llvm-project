// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s
// REQUIRES: debug-crt

#include <iostream>
#include <vector>

int unallocatedThing;

union AllocationEntry {
  unsigned long m_index;
  AllocationEntry *m_pNext;
};

void *Alloc(size_t numBytes) {
  AllocationEntry *pAllocationEntry =
      (AllocationEntry *)::operator new[](numBytes);
  return (void *)(pAllocationEntry + 1);
}

void Free(void *pAllocation) {
  AllocationEntry *pAllocationEntry = (AllocationEntry *)pAllocation - 1;
  if (!_CrtIsValidHeapPointer((const void *)pAllocationEntry)) {
    std::cerr << "Failed.\n";
    return;
  }
  free(pAllocationEntry);
}

void testCustomAlloc() {
  auto customPtr = Alloc(400);
  Free(customPtr);
}

void testValidation() {
  {
    char *myPtr = (char *)malloc(128);

    _CrtIsMemoryBlock((const void *)myPtr, sizeof(char) * 10, NULL, NULL, NULL);

    if (!_CrtIsValidPointer((const void *)myPtr, sizeof(char) * 10, true)) {
      std::cerr << "Failed.\n";
    }

    if (!_CrtIsValidHeapPointer((const void *)myPtr)) {
      std::cerr << "Failed.\n";
    }

    free(myPtr);
  }

  {
    int *ptr = new int(42);

    if (!_CrtIsValidHeapPointer(ptr)) {
      std::cerr << "Failed.\n";
    }

    delete ptr;

    if (_CrtIsValidHeapPointer(ptr)) {
      std::cerr << "Failed.\n";
    }
  }

  if (_CrtIsValidHeapPointer(&unallocatedThing)) {
    std::cerr << "Failed.\n";
  }
}

void testValidationAfterFree() {
  char *myPtr = (char *)malloc(128);
  if (!_CrtIsValidHeapPointer(myPtr)) {
    std::cerr << "Failed before free.\n";
  }

  free(myPtr);

  if (_CrtIsValidHeapPointer(myPtr)) {
    std::cerr << "Failed after free.\n";
  }
}

void testOffset() {
  auto customPtr = Alloc(400);
  auto offsetPtr = ((AllocationEntry *)customPtr) + 4;
  *offsetPtr = AllocationEntry{2};
  if (_CrtIsValidHeapPointer(offsetPtr)) {
    std::cerr << "Failed on offset address.\n";
  }
  Free(customPtr);
}

int main() {
  testCustomAlloc();
  testValidation();
  testValidationAfterFree();
  testOffset();

  std::cerr << "Success.\n";
  return 0;
}

// CHECK: Success.
// CHECK-NOT: {{.*Failed}}
// CHECK-NOT: {{.*ERROR: AddressSanitizer}}
