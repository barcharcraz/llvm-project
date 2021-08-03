#ifndef TEST_MSVC_HOST_H
#define TEST_MSVC_HOST_H

#if defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
unsigned int disable_abort_message_box = _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

#endif