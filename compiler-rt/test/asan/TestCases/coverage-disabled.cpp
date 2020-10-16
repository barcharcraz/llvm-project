// UNSUPPORTED: msvc-host
// Tracked by vso1226261, ( GeneralTestSuite_amd64chk_MD.txt GeneralTestSuite_amd64chk_MDd.txt GeneralTestSuite_amd64chk_MT.txt GeneralTestSuite_amd64chk_MTd.txt GeneralTestSuite_x86chk_MD.txt GeneralTestSuite_x86chk_MDd.txt GeneralTestSuite_x86chk_MT.txt GeneralTestSuite_x86chk_MTd.txt )
// Test that no data is collected without a runtime flag.
//
// RUN: rm -rf %t-dir
// RUN: mkdir -p %t-dir
//
// RUN: %clangxx_asan -fsanitize-coverage=func,trace-pc-guard %s -o %t
//
// RUN: %env_asan_opts=coverage_direct=0:coverage_dir='"%t-dir"':verbosity=1 %run %t
// RUN: not %sancov print %t-dir/*.sancov 2>&1
//
// UNSUPPORTED: android

int main(int argc, char **argv) {
  return 0;
}
