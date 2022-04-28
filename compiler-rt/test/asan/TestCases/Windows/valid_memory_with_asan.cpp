#include "Windows.h"
#include "malloc.h"

extern "C" __declspec(dllexport) int *AllocateMemory() {
  int *p = new int();
  return p;
}