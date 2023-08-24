#include "Windows.h"

extern "C" __declspec(dllexport) void FreeMemoryThunk(void *p) { free(p); }

extern "C" __declspec(dllexport) void FreeAlignedMemoryThunk(void *p) {
  _aligned_free(p);
}

extern "C" __declspec(dllexport) void *ReallocThunk(void *p, size_t size) {
  return realloc(p, size);
}

extern "C" __declspec(dllexport) void *RecallocThunk(void *p, size_t num,
                                                  size_t size) {
  return _recalloc(p, num, size);
}

extern "C" __declspec(dllexport) void *AlignedReallocThunk(void *p, size_t size,
                                                        size_t alignment) {
  return _aligned_realloc(p, size, alignment);
}

extern "C" __declspec(dllexport) void *AlignedRecallocThunk(void *p, size_t num,
                                                         size_t size,
                                                         size_t alignment) {
  return _aligned_recalloc(p, num, size, alignment);
}

extern "C" __declspec(dllexport) void *AlignedOffsetReallocThunk(void *p,
                                                              size_t size,
                                                              size_t alignment,
                                                              size_t offset) {
  return _aligned_offset_realloc(p, size, alignment, offset);
}

extern "C" __declspec(dllexport) void *AlignedOffsetRecallocThunk(
    void *p, size_t num, size_t size, size_t alignment, size_t offset) {
  return _aligned_offset_recalloc(p, num, size, alignment, offset);
}

extern "C" __declspec(dllexport) size_t MSizeThunk(void *memblock) {
  return _msize(memblock);
}

extern "C" __declspec(dllexport) size_t
    HeapSizeThunk(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
  return HeapSize(hHeap, dwFlags, lpMem);
}

extern "C" __declspec(dllexport) BOOL HeapLockThunk(HANDLE hHeap) {
  return HeapLock(hHeap);
}

extern "C" __declspec(dllexport) BOOL HeapUnlockThunk(HANDLE hHeap) {
  return HeapUnlock(hHeap);
}

extern "C" __declspec(dllexport) LPVOID
    HeapReAllocThunk(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
  return HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
}

extern "C" __declspec(dllexport) BOOL
    HeapFreeThunk(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
  return HeapFree(hHeap, dwFlags, lpMem);
}

extern "C" __declspec(dllexport) size_t
    AlignedMSizeThunk(void *memblock, size_t alignment, size_t offset) {
  return _aligned_msize(memblock, alignment, offset);
}

extern "C" __declspec(dllexport) UINT LocalFlagsThunk(HANDLE hMem) {
  return LocalFlags(hMem);
}

extern "C" __declspec(dllexport) LPVOID LocalLockThunk(HANDLE hMem) {
  return LocalLock(hMem);
}

extern "C" __declspec(dllexport) BOOL LocalUnlockThunk(HANDLE hMem) {
  return LocalUnlock(hMem);
}

extern "C" __declspec(dllexport) LPVOID LocalHandleThunk(HANDLE hMem) {
  return LocalHandle(hMem);
}

extern "C" __declspec(dllexport) LPVOID LocalFreeThunk(HANDLE hMem) {
  return LocalFree(hMem);
}

extern "C" __declspec(dllexport) size_t LocalSizeThunk(HANDLE hMem) {
  return LocalSize(hMem);
}

extern "C" __declspec(dllexport) HANDLE
    LocalReAllocThunk(HANDLE hMem, SIZE_T uBytes, UINT uFlags) {
  return LocalReAlloc(hMem, uBytes, uFlags);
}

extern "C" __declspec(dllexport) UINT GlobalFlagsThunk(HANDLE hMem) {
  return GlobalFlags(hMem);
}

extern "C" __declspec(dllexport) LPVOID GlobalLockThunk(HANDLE hMem) {
  return GlobalLock(hMem);
}

extern "C" __declspec(dllexport) BOOL GlobalUnlockThunk(HANDLE hMem) {
  return GlobalUnlock(hMem);
}

extern "C" __declspec(dllexport) LPVOID GlobalHandleThunk(HANDLE hMem) {
  return GlobalHandle(hMem);
}

extern "C" __declspec(dllexport) LPVOID GlobalFreeThunk(HANDLE hMem) {
  return GlobalFree(hMem);
}

extern "C" __declspec(dllexport) size_t GlobalSizeThunk(HANDLE hMem) {
  return GlobalSize(hMem);
}

extern "C" __declspec(dllexport) HGLOBAL
    GlobalReAllocThunk(HANDLE hMem, SIZE_T uBytes, UINT uFlags) {
  return GlobalReAlloc(hMem, uBytes, uFlags);
}