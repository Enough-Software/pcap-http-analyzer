#include "util.h"

#ifndef __APPLE__

#include <string.h>

const char* strnchr(const char* str, size_t len, int character) {
  const char* end = str + len;
  char c = (char) character;

  do {
    if (*str == c) {
      return str;
    }
  } while (++str < end);

  return NULL;
}

const char* strnstr(const char* str, const char* find, size_t len)
{
  char c, sc;
  size_t flen;

  if ((c = *find++) != '\0') {
    flen = strlen(find);

    do {
      do {
	if (len-- < 1 || (sc = *str++) == '\0') {
	  return NULL;
	}
      } while (sc != c);

      if (flen > len) {
	return NULL;
      }
    } while (strncmp(str, find, flen) != 0);

    str--;
  }

  return ((char*) str);
}

#endif /* __APPLE__ */
