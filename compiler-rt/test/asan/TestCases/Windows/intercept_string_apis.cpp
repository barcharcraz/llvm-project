// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1

// This test runs random string inputs on all the string APIs that we intercept to look for
// interception errors. The inputs are random because there have been interception errors
// that only trigger for specific inputs.

#include <Windows.h>
#include <algorithm>
#include <limits>
#include <random>
#include <stdio.h>
#include <string.h>
#include <system_error>
#include <vector>

using std::basic_string;
using std::generate;
using std::make_unsigned_t;
using std::max;
using std::mt19937_64;
using std::numeric_limits;
using std::random_device;
using std::seed_seq;
using std::string;
using std::system_category;
using std::uniform_int_distribution;
using std::vector;
using std::wstring;

static const vector<uint32_t> repro_seed; // = { SEED DATA HERE };

static void initialize_randomness(mt19937_64 &mt64) {
  constexpr size_t n = mt19937_64::state_size;
  constexpr size_t w = mt19937_64::word_size;
  static_assert(w % 32 == 0);
  constexpr size_t k = w / 32;

  vector<uint32_t> vec(n * k);

  if (repro_seed.size() == 0) {
    random_device rd;
    generate(vec.begin(), vec.end(), ref(rd));
    fputs("Generated seed data.\n", stderr);
  } else if (repro_seed.size() == vec.size()) {
    vec = repro_seed;
    fputs("Loaded seed data.\n", stderr);
  } else {
    fputs("ERROR: Invalid seed data.\n", stderr);
    exit(1);
  }

  fputs("This is a randomized test. Upon failure, rebuild test with seed data to reproduce.\n", stderr);
  fprintf(stderr, "SEED DATA:\n{ ");
  for (const auto &elem : vec) {
    fprintf(stderr, "%0u, ", elem);
  }
  fputs("}\n", stderr);

  seed_seq seq(vec.cbegin(), vec.cend());

  mt64.seed(seq);

  fputs("Successfully seeded mt64. First three values:\n", stderr);
  for (int i = 0; i < 3; ++i) {
    fprintf(stderr, "0x%16llx\n", mt64());
  }
}

class module {
public:
  module(const wchar_t *n) : _name(n), _handle(0) {
  }

  const wchar_t *name() const {
    return _name;
  }

  HMODULE handle() {
    if (!_handle) {
      _handle = LoadLibraryW(_name);
      if (!_handle) {
        const auto gle = GetLastError();
        fwprintf(stderr, L"Could not load '%s'.", _name);
        fprintf(stderr, "GetLastError() returned '0x%lx': '%s'\n", gle, system_category().message(gle).c_str());
        exit(gle);
      }
    }
    return _handle;
  }

private:
  const wchar_t *_name;
  HMODULE _handle;
};

static module modules[] = {
    //{L"msvcr100.dll"},
    //{L"msvcr110.dll"},
    //{L"msvcr120.dll"},
    {L"vcruntime140.dll"},
    {L"ucrtbase.dll"},
    {L"ntdll.dll"}};

struct test_data {
  string str1;
  string str2;
  wstring wstr;
};

struct intercept_test {
  const char *func_name;
  void (*test_function)(void *, const test_data &test);
};

// decltype won't work to detect signature on functions that have overloads
#define INTERCEPT_TEST_SIG(FUNC, SIG, ...)          \
  { #FUNC, [](void *__fp, const test_data &input) { \
    using fp_t = SIG;                               \
    fp_t FUNC{reinterpret_cast<fp_t>(__fp)};        \
    __VA_ARGS__                                     \
  }}
#define INTERCEPT_TEST(FUNC, ...) INTERCEPT_TEST_SIG(FUNC, decltype(&FUNC), __VA_ARGS__)

static const intercept_test tests[] = {
    INTERCEPT_TEST(strlen, {
      strlen(input.str1.c_str());
      strlen(input.str2.c_str());
    }),

    INTERCEPT_TEST(strnlen, {
      strnlen(input.str1.c_str(), input.str1.size());
      strnlen(input.str1.c_str(), input.str2.size());
      strnlen(input.str2.c_str(), input.str1.size());
      strnlen(input.str2.c_str(), input.str2.size());
    }),

    INTERCEPT_TEST(strcmp, {
      strcmp(input.str1.c_str(), input.str2.c_str());
    }),

    INTERCEPT_TEST(strncmp, {
      strncmp(input.str1.c_str(), input.str2.c_str(), input.str1.size());
      strncmp(input.str1.c_str(), input.str2.c_str(), input.str2.size());
    }),

    INTERCEPT_TEST_SIG(strstr, char *(*)(const char *, const char *), {
      strstr(input.str1.c_str(), input.str2.c_str());
      strstr(input.str2.c_str(), input.str1.c_str());
    }),

    INTERCEPT_TEST_SIG(strchr, char *(*)(const char *, int), {
      strchr(input.str1.c_str(), input.str2[0]);
      strchr(input.str2.c_str(), input.str1[0]);
    }),

    INTERCEPT_TEST(strspn, {
      strspn(input.str1.c_str(), input.str2.c_str());
      strspn(input.str2.c_str(), input.str1.c_str());
    }),

    INTERCEPT_TEST(strcspn, {
      strcspn(input.str1.c_str(), input.str2.c_str());
      strcspn(input.str2.c_str(), input.str1.c_str());
    }),

    INTERCEPT_TEST(strtok, {
      string mutable_str1(input.str1);
      string mutable_str2(input.str2);
      strtok(&mutable_str1[0], input.str2.c_str());
      strtok(&mutable_str2[0], input.str1.c_str());
    }),

    INTERCEPT_TEST_SIG(strpbrk, const char *(*)(const char *, const char *), {
      strpbrk(input.str1.c_str(), input.str2.c_str());
      strpbrk(input.str2.c_str(), input.str1.c_str());
    }),

    INTERCEPT_TEST(strcpy, {
      const size_t sz = (max)(input.str1.size(), input.str2.size()) + 1;
      char *buf = new char[sz];
      memset(buf, 0, sz);
      strcpy(buf, input.str1.c_str());
      strcpy(buf, input.str2.c_str());
      delete[] buf;
    }),

    INTERCEPT_TEST(strncpy, {
      const size_t sz = (max)(input.str1.size(), input.str2.size()) + 1;
      char *buf = new char[sz];
      memset(buf, 0, sz);
      strncpy(buf, input.str1.c_str(), sz);
      strncpy(buf, input.str2.c_str(), sz);
      delete[] buf;
    }),

    INTERCEPT_TEST(strcat, {
      const size_t sz = input.str1.size() + input.str2.size() + 1;
      char *buf = new char[sz];
      memset(buf, 0, sz);
      strcat(buf, input.str1.c_str());
      strcat(buf, input.str2.c_str());
      delete[] buf;
    }),

    INTERCEPT_TEST(strncat, {
      const size_t sz = input.str1.size() + input.str2.size() + 1;
      char *buf = new char[sz];
      memset(buf, 0, sz);
      strncat(buf, input.str1.c_str(), sz);
      strncat(buf, input.str2.c_str(), sz);
      delete[] buf;
    }),

    INTERCEPT_TEST(_strdup, {
      free(_strdup(input.str1.c_str()));
      free(_strdup(input.str1.c_str()));
    }),

    INTERCEPT_TEST(wcslen, {
      wcslen(input.wstr.c_str());
    }),

    INTERCEPT_TEST(wcsnlen, {
      wcsnlen(input.wstr.c_str(), input.wstr.size());
    }),

    INTERCEPT_TEST(atoi, {
      atoi(input.str1.c_str());
      atoi(input.str2.c_str());
    }),

    INTERCEPT_TEST(atol, {
      atol(input.str1.c_str());
      atol(input.str2.c_str());
    }),

    INTERCEPT_TEST(strtol, {
      char *end;
      strtol(input.str1.c_str(), &end, 36);
      strtol(input.str2.c_str(), &end, 36);
    })};

template <typename CharType>
basic_string<CharType> generate_random_string(mt19937_64 &mt64) {
  uniform_int_distribution<size_t> str_len_dist(0, 1024);
  uniform_int_distribution<unsigned int> char_dist(1, (numeric_limits<make_unsigned_t<CharType>>::max)());

  const size_t len = str_len_dist(mt64);
  basic_string<CharType> s(len, '\0');
  generate(s.begin(), s.end(), [&]() { return static_cast<CharType>(char_dist(mt64)); });

  return s;
}

vector<test_data> generate_random_tests(const size_t num_generated, mt19937_64 &mt64) {
  vector<test_data> tests(num_generated);
  generate(tests.begin(), tests.end(), [&]() -> test_data {
    return {generate_random_string<char>(mt64), generate_random_string<char>(mt64), generate_random_string<wchar_t>(mt64)};
  });
  return tests;
}

int main() {
  mt19937_64 mt64;
  initialize_randomness(mt64);

  auto test_strings = generate_random_tests(100, mt64);

  for (auto &dll : modules) {
    fwprintf(stderr, L"Testing '%s'\n", dll.name());

    for (const auto &test : tests) {
      void *fp = GetProcAddress(dll.handle(), test.func_name);
      if (fp == nullptr) {
        continue;
      }

      fprintf(stderr, "\ttesting %s: ", test.func_name);

      for (const auto &test_input : test_strings) {
        test.test_function(fp, test_input);
      }

      fputs("PASS\n", stderr);
    }
  }

  return 0;
}