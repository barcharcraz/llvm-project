// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s

#include <atomic>
#include <iostream>
#include <ppl.h>
#include <vector>

int main() {
  std::atomic<uint32_t> matches(0);
  static uint32_t const cTasks = 32;

  concurrency::task_group tasks;
  for (uint32_t iTask = 0; iTask < cTasks; iTask++) {
    tasks.run([&matches]() { ++matches; });
  }

  tasks.wait();
  if (cTasks != matches.load()) {
    std::cerr << "Failed.\n";
  }

  std::cerr << "Success.\n";
  return 0;
}

// CHECK: Success.
// CHECK-NOT: Failed.
// CHECK-NOT: {{.*ERROR: AddressSanitizer}}