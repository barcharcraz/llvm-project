// Without ASan's new/delete operators, new-delete-type-mismatch errors are not detected.

// RUN: %clang_cl_asan -Od %s -Fe%t %nonewdelete_link
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

// Taken from: https://docs.microsoft.com/en-us/cpp/sanitizers/error-new-delete-type-mismatch
int main() {
    Base *b = new Derived;

    delete b;  // Boom! (legitimate error but should be missed without new/delete overrides)

    std::unique_ptr<Base> b1 = std::make_unique<Derived>();

    printf("success\n");
    return 0;
}
// CHECK: success