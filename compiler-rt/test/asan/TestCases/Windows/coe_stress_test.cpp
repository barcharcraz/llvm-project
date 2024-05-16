// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s

// Stress test for destroying metadata and recovering during continue-on-error
#include <iostream>
#include <cstdio>
#include <string>

struct Base {
  // Purposefully leave out virtual destructor for errors
  //virtual ~Base() = default;
};

struct Derived : public Base {
  std::wstring Value = L"Leaked if Base destructor is not virtual!";
};

constexpr size_t numPoints = 3;
double pointsInGlobalData[numPoints] = {1.0, 2.0, 3.0};
constexpr auto loopCount = 2;

int main() {

  pointsInGlobalData[3] = 3.0; // CHECK: {{.*ERROR: AddressSanitizer: global-buffer-overflow}}

  for (auto i = 0; i < loopCount; ++i) {

    double pointOnStack[numPoints] = {1.0, 2.0, 3.0};

    // This clobbers metadata for next report of an underflow
    pointOnStack[-1] = 3.0; // CHECK: {{.*ERROR: AddressSanitizer: stack-buffer-underflow}}

    // Repair metadata before reporting heap buffer overflow.
    // The previous underflow above clobbered the meta-data
    // required for the ability to report this error.
    pointOnStack[numPoints] = 0.0; // CHECK: {{.*ERROR: AddressSanitizer: stack-buffer-overflow}}

    // Large object heap
    // Note there are two ASan allocators.
    // Use secondary_ allocator from the combined allocator
    // and blow up that metadata which is different from primary_
    // metadata which is based on a SizeClassAllocator.
    double *pointOnHeap = new double[numPoints + 100000];

    // Clobber metadata for the delete/quarantine of pointOnHeap array
    pointOnHeap[-1] = 4.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    delete[] pointOnHeap;

    // Repair broken error report for use after free underflow
    // The error will have 3 call stacks showing an underflow on
    // storage that' has been deleted
    pointOnHeap[-1] = 5.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    double *pointsOnLittleHeap = new double[numPoints];
    pointsOnLittleHeap[-1] = 5.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}
    pointsOnLittleHeap[numPoints] = 0.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    auto getMessageFaulty = [](){
      std::string s = "Buffer used after object was destroyed";
      return s.data();
    };
    printf_s(
        "%s\r\n",
        getMessageFaulty()); // CHECK: {{.*ERROR: AddressSanitizer: heap-use-after-free}}

    double *pointDoubleFree = new double[numPoints]{1.0, 2.0, 3.0};
    delete[] pointDoubleFree;
    pointDoubleFree[-1] = 4.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}
    delete[] pointDoubleFree; // CHECK: {{.*ERROR: AddressSanitizer: attempting double-free}}

    // Non-virtual base class destructor.
    Base *base = new Derived();
    delete base; // CHECK: {{.*ERROR: AddressSanitizer: new-delete-type-mismatch}}

    double *pointsMalloc = (double *)malloc(numPoints * sizeof(double));
    pointsMalloc[0] = 1.0;
    pointsMalloc[1] = 2.0;
    pointsMalloc[2] = 3.0;

    double *oldBuffer = pointsMalloc;

    // Clobber the stored user_requested_size metadata
    pointsMalloc[-1] = 2.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    // This _msize is broken by the [-1] underflow above, which clobbers
    // user_requested_size attempting to call malloc_usable_size() for
    // pointer which is not owned
    size_t size = _msize(oldBuffer);

    // Clobber metadata to screw up the realloc
    pointsMalloc[-1] = 2.0; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    if ((pointsMalloc = (double *)realloc(
             pointsMalloc, size + (100 * sizeof(double)))) == nullptr) {
      free(oldBuffer); // Free original block and die
      exit(1);
    }

    // Buffer overflow in between small allocations
    pointsMalloc[5] = 5.0;

    // Create a buffer in the heap and clobber the metadata
    // for the next allocation, the "kAllocBeginMagic" and the pointer
    // to the "user_begin" section of the allocation.
    constexpr size_t buff_size = 128;
    char *buffer = new char[buff_size];
    std::memset(buffer, '\0', buff_size);

    // The memset clobbers both the 2 metadata fields mentioned above
    // but also clobbers the AsanChunk which is in the padding associated
    // with the left red zone (for the adjacent allocation block)
    std::memset(
        &buffer[buff_size - 28], '=',
        30); // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}

    // Hidden subtlety:
    // The previous error report triggers the allocator to place other blocks into quarantine
    // Note that Asan never deletes or frees. The memset above clobbers metadata
    // which then could cause recycle in quarantine to deadlock.
    //
    // TODO: This is sometimes printed as a unique error twice with the same message. The first is "wild pointer"
    // and the second is fully described.
    buffer[buff_size] = '\0'; // CHECK: {{.*ERROR: AddressSanitizer: heap-buffer-overflow}}
  }

  double *pointsMalloc = (double *)malloc((size_t)(20000 * sizeof(double)));
  pointsMalloc[0] = 1.0;
  pointsMalloc[1] = 2.0;
  pointsMalloc[2] = 3.0;

  // Test we still print after all those errors
  std::cerr << "pointsMalloc: " << pointsMalloc[0] << " " << pointsMalloc[1]
            << " " << pointsMalloc[2] << std::endl;

  // CHECK: pointsMalloc: 1 2 3
  // CHECK: >>>Total: {{15|16}} Unique Memory Safety Issues (based on call stacks not source position) <<<
}