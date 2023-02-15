// RUN: %clang_cl /Od %s -Fe%t
// RUN:  %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s

// CHECK-NOT: ERROR
// CHECK-NOT: AddressSanitizer

#include <Windows.h>
#include <stdio.h>


int main() {
  
  size_t sz = 8;
  char* fixed = (char *)LocalAlloc(LMEM_FIXED, sz);

  size_t new_sz = 64;
  char* still_fixed = (char *)LocalReAlloc(fixed, new_sz, GMEM_MODIFY | GMEM_MOVEABLE);
  char* backing_ptr = (char*)LocalLock(still_fixed);
    fprintf(stderr, "backing_ptr: %zx moveable: %zx fixed: %zx\n", (size_t)backing_ptr, (size_t)still_fixed, (size_t)fixed);
  if (!(backing_ptr == still_fixed || still_fixed == fixed)) {
      fprintf(stderr, "ERROR: FIXED TO MOVEABLE CONVERSION IS NOT PERMITTED WITH LOCALALLOC");
      return 0;
  }
  size_t returned_size = LocalSize(still_fixed);
  if (returned_size == new_sz) {
      fprintf(stderr, "ERROR: NEW SIZE WAS NOT IGNORED"); 
      //this is a weird quirk of LocalReAlloc, MODIFY only changes 
      // discardable state if it's specified.
      return 0;
  }
  
  fixed = (char *)LocalReAlloc(still_fixed, new_sz, GMEM_MODIFY);
  // conversion is one way, realloc shouldn't happen here.
  if (still_fixed != fixed) {
      fprintf(stderr, "ERROR: MOVEABLE TO FIXED CONVERSION FAIL");
      return 0;
  }
  //LMEM_MODIFY should still ignore the size change.
  returned_size = LocalSize(still_fixed);
  if (returned_size == new_sz) {
      fprintf(stderr, "ERROR: NEW SIZE (2nd CALL) WAS NOT IGNORED");
      return 0;
  }
  fixed[0] = 0xff;
  return 0;
}