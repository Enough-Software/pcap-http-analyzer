#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>

#ifndef HAVE_STRNCHR
const char* strnchr(const char* str, size_t len, int character);
#endif /* HAVE_STRNCHR */

#ifndef HAVE_STRNSTR
const char* strnstr(const char* str, const char* find, size_t len);
#endif /* HAVE_STRNSTR */

#endif /* __UTIL_H__ */
