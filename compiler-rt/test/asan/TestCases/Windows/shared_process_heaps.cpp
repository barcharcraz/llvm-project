// RUN: %clang_cl_asan -Od %s /std:c++17 /DASAN_PROCESS -Fe%tSend
// RUN: %clang_cl_asan -Od %s /std:c++17 -Fe%tReceive
// RUN: ((%run %tSend | %run %tReceive) 2>&1 ) | FileCheck %s

#include <iostream>
#include <windows.h>

static std::string mappingName = "Global\\MappingObject";
static std::string message = "Message from ASAN process.";
static std::string eventToReceive = "eventToReceive";
constexpr auto bufferSize = 256;
constexpr auto sectionSize = 1024;

using ReAllocateFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, SIZE_T);
using RtlCreateHeapFunctionPtr = PVOID(__stdcall *)(ULONG, PVOID, SIZE_T,
                                                    SIZE_T, PVOID, PVOID);

ReAllocateFunctionPtr RtlAllocateHeapPtr;
RtlCreateHeapFunctionPtr RtlCreateHeapPtr;

// Acquire pointers to necessary RTL functions for testing
void InitializeFunctions() {
#if ASAN_PROCESS
  HMODULE NtDllHandle = GetModuleHandle("ntdll.dll");
  if (!NtDllHandle) {
    // CHECK-NOT: Couldn't load ntdll.
    std::cerr << "Couldn't load ntdll." << std::endl;
  }

  RtlCreateHeapPtr =
      (RtlCreateHeapFunctionPtr)GetProcAddress(NtDllHandle, "RtlCreateHeap");
  if (!RtlCreateHeapPtr) {
    // CHECK-NOT: Couldn't find RtlCreateHeap.
    std::cerr << "Couldn't find RtlCreateHeap." << std::endl;
  }

  RtlAllocateHeapPtr =
      (ReAllocateFunctionPtr)GetProcAddress(NtDllHandle, "RtlAllocateHeap");
  if (!RtlAllocateHeapPtr) {
    // CHECK-NOT: Couldn't find RtlAllocateHeap.
    std::cerr << "Couldn't find RtlAllocateHeap." << std::endl;
  }
#endif
}

int Fail(const char *message = "") {
  std::cerr << message << std::endl;
  return EXIT_FAILURE;
}

// Handles shared process memory allocation
// and reading from shared process memory
struct SharedProcessMemory {
  SharedProcessMemory() { InitializeFunctions(); }

  ~SharedProcessMemory() {
    UnmapViewOfFile(SharedMemory);
    CloseHandle(FileMapping);
  }

  bool IsOutOfHeap(int offset) {
    return offset < 0 || (offset / 8) > sectionSize;
  }

  int TriggerEvent() {
    auto eventToOtherProcess =
        CreateEvent(nullptr, false, false, eventToReceive.data());
#if ASAN_PROCESS

    if (AllocateSharedMemory() != EXIT_SUCCESS) {
      return Fail();
    }

    if (!SetEvent(eventToOtherProcess)) {
      // CHECK-NOT: Failed to notify other process.
      return Fail("Failed to notify other process.");
    }

    fputs("Success.", stderr);
    return EXIT_SUCCESS;
#else

    // Wait for the event sent from the ASAN process
    DWORD wait = WaitForSingleObject(eventToOtherProcess, 5000);
    if (wait != WAIT_OBJECT_0) {
      // CHECK-NOT: Failed to wait on ASAN Process.
      return Fail("Failed to wait on ASAN Process.");
    }

    return ReadSharedMemory();
#endif
  }

  int AllocateSharedMemory() {

    // Create shared process memory to create a private heap in
    // clang-format off
    FileMapping = ::CreateFileMapping(
        INVALID_HANDLE_VALUE,                          // use paging file
        NULL,                                          // default security
        PAGE_READWRITE,                                // read/write access
        0,                                             // maximum object size (high-order DWORD)
        bufferSize,                                    // maximum object size (low-order DWORD)
        reinterpret_cast<LPCSTR>(mappingName.data())); // name of mapping object
    // clang-format on

    if (!FileMapping) {
      // CHECK-NOT: Failed to create file mapping.
      return Fail("Failed to create file mapping.");
    }

    // Map the view of the shared section memory passed in
    SharedMemory = reinterpret_cast<BYTE *>(
        MapViewOfFile(FileMapping, FILE_MAP_ALL_ACCESS, 0, 0, bufferSize));
    if (!SharedMemory) {
      // CHECK-NOT: Failed to create shared memory.
      return Fail("Failed to create shared memory.");
    }

    // Create a heap inside of the shared memory region
    //
    // NOTE:
    // The growable flag must not be passed in for this test, as that
    // could change where the heap is allocated depending on the allocation
    // request
    HeapInSharedMemory =
        RtlCreateHeapPtr(HEAP_NO_SERIALIZE, SharedMemory, sectionSize,
                         sectionSize, nullptr, nullptr);

    if (!HeapInSharedMemory) {
      // CHECK-NOT: Failed to create heap in shared heap.
      return Fail("Failed to create heap in shared heap.");
    }

    // Attempt to allocate inside of the heap located inside of the shared memory region
    BufferInHeap =
        (char *)RtlAllocateHeapPtr(HeapInSharedMemory, 0, message.size());

    if (!BufferInHeap) {
      // CHECK-NOT: Failed to allocate in shared heap.
      return Fail("Failed to allocate in shared heap.");
    }

    // Copy a string into the buffer allocated above for the other process to read
    CopyMemory((PVOID)BufferInHeap, message.c_str(),
               message.size() * sizeof(char));

    // Place the relative offset at the beginning of the shared memory
    *reinterpret_cast<long long *>(SharedMemory) =
        BufferInHeap - HeapInSharedMemory;

    // The offset must lie inside of the heap range
    if (auto offset = *reinterpret_cast<long long *>(SharedMemory);
        IsOutOfHeap(offset)) {
      // CHECK-NOT: Sent out of range offset.
      return Fail("Sent out of range offset.");
    }
    return EXIT_SUCCESS;
  }

  int ReadSharedMemory() {
    FileMapping = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE,
                                  reinterpret_cast<LPCSTR>(mappingName.data()));

    if (!FileMapping) {
      // CHECK-NOT: Could not open file mapping object.
      return Fail("Could not open file mapping object.");
    }

    SharedMemory = reinterpret_cast<BYTE *>(
        MapViewOfFile(FileMapping, FILE_MAP_ALL_ACCESS, 0, 0, bufferSize));
    int offset = *reinterpret_cast<int *>(SharedMemory);

    if (!SharedMemory) {
      // CHECK-NOT: Could not map view of file.
      return Fail("Could not map view of file.");
    }

    if (IsOutOfHeap(offset)) {
      // CHECK-NOT: Virtual Address offset received is out of range.
      return Fail("Virtual Address offset received is out of range.");
    }

    auto asanProcessMessage = reinterpret_cast<char *>(
        reinterpret_cast<BYTE *>(SharedMemory) + offset);

    if (std::string(asanProcessMessage, message.size()).compare(message) == 0) {
      fputs("Success.", stderr);
      return EXIT_SUCCESS;
    } else {
      return Fail("Sent and received messages differ.");
    }
  }

  char *BufferInHeap = nullptr;
  HANDLE FileMapping = nullptr;
  PVOID HeapInSharedMemory = nullptr;
  BYTE *SharedMemory = nullptr;
};

int main() {
  SharedProcessMemory memory;
  return memory.TriggerEvent();
  // CHECK: Success.
}
