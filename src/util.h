#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>

const char* strnchr(const char* str, size_t len, int character);
const char* strnstr(const char* str, const char* find, size_t len);

#endif /* __UTIL_H__ */
