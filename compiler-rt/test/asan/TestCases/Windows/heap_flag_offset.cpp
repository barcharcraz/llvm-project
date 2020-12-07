// RUN: %clang_cl /Od %s -Fe%t
// RUN: %run %t
// Check that the hack we use to grab flags from a heap entry
// hasn't changed.
#include <Windows.h>

struct MOCK_HEAP {
#ifdef _WIN64
  unsigned long padding[28];
#else
  unsigned long padding[16];
#endif
  unsigned long flags;
  unsigned long forceflags;
};

#define GETFLAGS(heap) ((MOCK_HEAP *)heap)->flags
int main() {
  constexpr unsigned long FLAGS =
      HEAP_CREATE_ENABLE_EXECUTE | HEAP_NO_SERIALIZE;

  HANDLE heap = HeapCreate(FLAGS, 0x1000, 0x5000);

  if ((GETFLAGS(heap) & FLAGS) != FLAGS) {
    return -1;
  }

  return 0;
}
