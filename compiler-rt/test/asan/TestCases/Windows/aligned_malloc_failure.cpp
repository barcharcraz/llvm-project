// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=allocator_may_return_null=true %run %t

#include <Windows.h>

int main(){
    // Should return null and set errno to EINVAL
    // since this alignment of 5 is not valid.
    void* ptr = _aligned_malloc(8,5); 
    return (ptr == nullptr && errno == EINVAL) ? 0 : -1;
}