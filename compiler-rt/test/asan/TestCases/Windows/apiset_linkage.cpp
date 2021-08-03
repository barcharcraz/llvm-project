// Build-only test to ensure ASAN can link with APISET-only versions of umbrella libraries.
// RUN: %clang_cl_asan %s -Fe%t /link /NODEFAULTLIB:kernel32 /NODEFAULTLIB:onecore /NODEFAULTLIB:onecoreuap /DEFAULTLIB:onecore_apiset.lib
// RUN: %clang_cl_asan %s -Fe%t /link /NODEFAULTLIB:kernel32 /NODEFAULTLIB:onecore /NODEFAULTLIB:onecoreuap /DEFAULTLIB:onecoreuap_apiset.lib

int main()
{
    return 0;
}
