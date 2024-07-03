// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t
// FIXME: errno is crt state, not reflected
// XFAIL: debug-crt, (asan-static-runtime && target={{.*-windows-.*}})
#include <Windows.h>

int main(){
    // Should return null and set errno to EINVAL
    // since this alignment of 5 is not valid.
    void* ptr = _aligned_malloc(8,5);
    if (ptr != nullptr || errno != EINVAL)
      return -1;
    ptr = _aligned_offset_malloc(8, 5, 65);
    if (ptr != nullptr || errno != EINVAL)
      return -1;
    ptr = _aligned_offset_realloc(ptr, 12, 5, 65);
    if (ptr != nullptr || errno != EINVAL)
      return -1;
    ptr = _aligned_offset_recalloc(ptr, 2, 12, 5, 65);
    if (ptr != nullptr || errno != EINVAL)
      return -1;
    return 0;
}