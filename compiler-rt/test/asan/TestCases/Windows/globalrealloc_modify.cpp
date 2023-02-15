// RUN: %clang_cl /Od %s -Fe%t
// RUN:  %run %t 2>&1 | FileCheck %s

// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s
// CHECK-NOT: ERROR
// CHECK-NOT: AddressSanitizer

#include <Windows.h>
#include <stdio.h>

/* GlobalReAlloc and LocalReAlloc don't behave the same. 
   GlobalReAlloc allows the user to modify a pointer from fixed to moveable. LocalReAlloc doesn't.
*/

int main() {

  size_t sz = 8;
  char *fixed = (char *)GlobalAlloc(GMEM_FIXED, sz);

  size_t new_sz = 64;
  char *moveable = (char *)GlobalReAlloc(fixed, new_sz, GMEM_MODIFY | GMEM_MOVEABLE);
  char *backing_ptr = (char *)GlobalLock(moveable);
  fprintf(stderr, "backing_ptr: %zx moveable: %zx fixed: %zx\n", (size_t)backing_ptr, (size_t)moveable, (size_t)fixed);
  if (backing_ptr == moveable || moveable == fixed) {
    fprintf(stderr, "ERROR: FIXED TO MOVEABLE CONVERSION FAIL");
    return 0;
  }
  size_t returned_size = GlobalSize(moveable);
  if (returned_size == new_sz) {
    fprintf(stderr, "ERROR: NEW SIZE WAS NOT IGNORED"); //this is a weird quirk of GlobalRealloc in msdn.
    return 0;
  }

  fixed = (char *)GlobalReAlloc(moveable, new_sz, GMEM_MODIFY);
  // conversion is one way, fixed to moveable.
  if (moveable != fixed) {
    fprintf(stderr, "ERROR: MOVEABLE TO FIXED CONVERSION FAIL");
    return 0;
  }
  //GMEM_MODIFY should still ignore the size change.
  returned_size = GlobalSize(moveable);
  if (returned_size == new_sz) {
    fprintf(stderr, "ERROR: NEW SIZE (2nd CALL) WAS NOT IGNORED");
    return 0;
  }
  fixed[0] = 0xff;
  return 0;
}