// RUN: %libomp-compile-and-run
// Visual Studio C/C++ compiler currently supports only OpenMP version 2.5 and 
// tasking-related features from OpenMP 3.1 (plus minimal support for SIMD)
// UNSUPPORTED: msvc-19

/*
 GCC failed this test because __kmp_get_gtid() instead of __kmp_entry_gtid()
 was called in xexpand(KMP_API_NAME_GOMP_TASKGROUP_START)(void).
 __kmp_entry_gtid() will initialize the runtime if not yet done which does not
 happen with __kmp_get_gtid().
 */

int main()
{
    #pragma omp taskgroup
    { }

    return 0;
}
