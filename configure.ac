#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([gotgt], [0.1.0], [github.com/gostor])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_RANLIB
AC_CANONICAL_BUILD

case $build_os in
	darwin*)
		AM_CONDITIONAL([ON_DARWIN], [ true ])
		;;
	*)
		AM_CONDITIONAL([ON_DARWIN], [ false ])
		;;
esac

# Checks for go tool chain
AC_CHECK_PROG([has_go], [go], [yes], [no])
if test "x$has_go" != "xyes" ; then
    AC_MSG_ERROR(Unable to find go binary in PATH)
fi

# Platform specific setup
AC_CANONICAL_HOST

case $host_os in
	linux*) AM_CONDITIONAL([ON_LINUX], [ true  ]) ;;
	*)      AM_CONDITIONAL([ON_LINUX], [ false ]) ;;
esac

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strdup])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

AC_MSG_RESULT([
	${PACKAGE}  ${VERSION}
	build OS:   ${build_os}
	prefix:	    ${prefix}

	has go:     ${has_go}
])
