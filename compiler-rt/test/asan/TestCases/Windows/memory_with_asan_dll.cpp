#include "Windows.h"

extern "C" __declspec(dllexport) void FreeMemory(int *p) {
  free(p);
}

extern "C" __declspec(dllexport) void FreeAlignedMemory(int *p) {
  _aligned_free(p);
}

extern "C" __declspec(dllexport) void *Realloc(int *p, size_t size) {
  return realloc(p, size);
}

extern "C" __declspec(dllexport) void *Recalloc(int *p, size_t num, size_t size) {
  return _recalloc(p, num, size);
}

extern "C" __declspec(dllexport) void *AlignedRealloc(int *p, size_t size, size_t alignment) {
  return _aligned_realloc(p, size, alignment);
}

extern "C" __declspec(dllexport) void *AlignedRecalloc(int *p, size_t num, size_t size, size_t alignment) {
  return _aligned_recalloc(p, num, size, alignment);
}

extern "C" __declspec(dllexport) LPVOID MyLocalLock(HLOCAL hMem) {
  return LocalLock(hMem);
}

extern "C" __declspec(dllexport) BOOL MyLocalUnlock(HLOCAL hMem) {
  return LocalUnlock(hMem);
}

extern "C" __declspec(dllexport) LPVOID MyGlobalLock(HLOCAL hMem) {
  return GlobalLock(hMem);
}

extern "C" __declspec(dllexport) BOOL MyGlobalUnlock(HLOCAL hMem) {
  return GlobalUnlock(hMem);
}