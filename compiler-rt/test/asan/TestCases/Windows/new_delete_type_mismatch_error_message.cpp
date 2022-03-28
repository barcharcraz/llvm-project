// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <memory>
#include <vector>

struct T {
    T() : v(100) {}
    std::vector<int> v;
};

struct Base {};

struct Derived : public Base {
    T t;
};

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-new-delete-type-mismatch
int main() {
    Base *b = new Derived;

    delete b;  // Boom! 
    // CHECK: ERROR: AddressSanitizer: new-delete-type-mismatch on [[ADDR:0x[0-9a-f]+]] in thread T0:
    // CHECK-NEXT: object passed to delete has wrong type:
    // CHECK-NEXT: size of the allocated type:   {{[0-9]+}} bytes;
    // CHECK-NEXT: size of the deallocated type: {{[0-9]+}} bytes.
    // CHECK: [[ADDR]] is located {{[0-9]+}} bytes inside of {{[0-9]+}}-byte region [{{0x[0-9a-f]+}},{{0x[0-9a-f]+}})
    // CHECK-NEXT: allocated by thread T0 here:
    // CHECK: SUMMARY: AddressSanitizer: new-delete-type-mismatch
    // CHECK: HINT: if you don't care about these errors you may set ASAN_OPTIONS=new_delete_type_mismatch=0

    std::unique_ptr<Base> b1 = std::make_unique<Derived>();

    return 0;
}