AC_INIT([pcap_dump],[0.1])
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_HEADER_STDBOOL
AC_CHECK_FUNCS([inet_ntoa memmove strchr strdup strstr])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AH_TEMPLATE([ENABLE_JSON], [Define to one if JSON support is enabled.])
AC_ARG_ENABLE(json,
  [  --enable-json           Enables JSON parsing and pretty output. Needs json-glib-1.0.],
  [
    PKG_CHECK_MODULES([JSON], [json-glib-1.0 >= 0.14])
    AC_DEFINE([ENABLE_JSON], [1], [])
  ])
AM_MAINTAINER_MODE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES(Makefile)
AC_OUTPUT

