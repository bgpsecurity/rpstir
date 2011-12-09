#/* ***** BEGIN LICENSE BLOCK *****
# *
# * BBN Address and AS Number PKI Database/repository software
# * Version 3.0-beta
# *
# * US government users are permitted unrestricted rights as
# * defined in the FAR.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT
# * WARRANTY OF ANY KIND, either express or implied.
# *
# * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# *
# * Contributor(s):  Brenton Kohler
# *
# * ***** END LICENSE BLOCK ***** */
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(resource-PKI, 0.01, mreynolds@bbn.com)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
# The following would default to silent, but depends on GNU make behavior.
# AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([rtr/pdu.h])

AM_MAINTAINER_MODE
: ${CFLAGS=""}
# Checks for programs.
#AC_PROG_CXX
AC_PROG_CC
#AC_PROG_AWK
AC_PROG_MAKE_SET
AC_PROG_RANLIB
#AC_PROG_LIBTOOL
AC_PROG_SED


AC_ARG_WITH(
    [ssl-include],
    AS_HELP_STRING([--with-ssl-include],[Path to openssl library install location: Defaults to /usr/local/ssl/include ]),
    [ ssl_include=$withval],
    [ ssl_include=/usr/local/ssl/include]
)

AC_ARG_WITH(
    [ssl-lib],
    AS_HELP_STRING([--with-ssl-lib],[Path to openssl library install location: Defaults to /usr/local/ssl/lib ]),
    [ ssl_lib=$withval],
    [ ssl_lib=/usr/local/ssl/lib]
)

AC_ARG_WITH(
    [cryptlib-include],
    AS_HELP_STRING([--with-cryptlib-include],[Path to cryptlib install location: Defaults to /usr/local/include ]),
    [ cryptlib_include=$withval],
    [ cryptlib_include=/usr/local/include]
)

AC_ARG_WITH(
    [odbc-include],
    AS_HELP_STRING([--with-odbc-include],[Path to odbc include files: Defaults to /usr/local/include ]),
    [ odbc_include=$withval],
    [ odbc_include=/usr/local/include]
)

AC_ARG_WITH(
    [cryptlib-lib],
    AS_HELP_STRING([--with-cryptlib-lib],[Path to cryptlib install location: Defaults to /usr/local/lib ]),
    [ cryptlib_lib=$withval],
    [ cryptlib_lib=/usr/local/lib]
)

AC_ARG_WITH(
    [odbc-lib],
    AS_HELP_STRING([--with-odbc-lib],[Path to odbc install location: Defaults to /usr/local/lib ]),
    [ odbc_lib=$withval],
    [ odbc_lib=/usr/local/lib]
)

AC_ARG_WITH(
    [mysql-config],
    AS_HELP_STRING([--with-mysql-config],[Path to mysql_config executable ]),
    [ mysql_config=$withval],
    [ mysql_config=mysql_config]
)

if test x${ssl_lib} != x; then
  LDFLAGS="-L${ssl_lib} -Wl,-rpath -Wl,${ssl_lib} ${LDFLAGS-}"
fi
if test x${odbc_lib} != x; then
  LDFLAGS="-L${odbc_lib} -Wl,-rpath -Wl,${odbc_lib} ${LDFLAGS-}"
fi
if test x${cryptlib_lib} != x; then
  LDFLAGS="-L${cryptlib_lib} -Wl,-rpath -Wl,${cryptlib_lib} ${LDFLAGS-}"
fi

if test x${odbc_include} != x; then
  CFLAGS="-isystem${odbc_include} ${CFLAGS-}"
fi
if test x${cryptlib_include} != x; then
  CFLAGS=" -isystem${cryptlib_include} ${CFLAGS-}"
fi
if test x${ssl_include} != x; then
  CFLAGS="-isystem${ssl_include} ${CFLAGS-}"
fi

AC_PATH_PROG(MYSQL_CONFIG, ${mysql_config})
if test "x${MYSQL_CONFIG}" != x -a -x "${MYSQL_CONFIG}"; then
  # this is a bit of a hack because mysql_config --include specified non-system include flags
  for flag in `$MYSQL_CONFIG --include`; do
    case $flag in
      -I*)
        dir="`echo $flag | $SED 's/^-I//'`"
        CPPFLAGS="-isystem${dir} $CPPFLAGS"
        ;;
      *)
        CPPFLAGS="$flag $CPPFLAGS"
        ;;
    esac
  done

  # this is a bit of a hack because mysql_config --libs_r specifies compiler flags, not linker flags
  for flag in `$MYSQL_CONFIG --libs_r`; do
    case $flag in
      -L*)
        libpath="`echo $flag | $SED 's/^-L//'`"
        LDFLAGS="-L${libpath} -Wl,-rpath -Wl,${libpath} ${LDFLAGS}"
        ;;
      -l*)
        LDFLAGS="${flag} ${LDFLAGS}"
        ;;
      *)
        ;;
    esac
  done
else
  AC_MSG_ERROR([cannot find or execute mysql_config, make sure MySQL client is installed])
fi

#Check for GCC Stack-Smashing Protector and enable in some cases
#  If --enable-stack-protector is specified: enable it
#  Else if --disable-stack-protector is specified: don't enable it
#  Else if C compiler supports it: enable it
#  Else: don't enable it
AC_MSG_CHECKING([whether C compiler supports -fstack-protector])
CFLAGS_RESTORE="${CFLAGS-}"
CFLAGS="${CFLAGS-} -fstack-protector"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
    [AC_MSG_RESULT([yes]); HAVE_STACK_PROTECTOR=yes],
    [AC_MSG_RESULT([no]);  HAVE_STACK_PROTECTOR=no])
CFLAGS="${CFLAGS_RESTORE-}"
AC_ARG_ENABLE(
    [stack-protector],
    AS_HELP_STRING([--enable-stack-protector],[Whether or not to add -fstack-protector to CFLAGS: Defaults to yes when using gcc and no otherwise ]),
    [ if test x"$enableval" != xno; then CFLAGS="${CFLAGS-} -fstack-protector"; fi ],
    [ if test x"$HAVE_STACK_PROTECTOR" = xyes; then CFLAGS="${CFLAGS-} -fstack-protector"; fi ]
)

#Checks for libraries.
AC_SEARCH_LIBS([pthread_create],[pthread],[],[
	echo "Error: libpthread is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([dlopen],[dl],[],[
	echo "Error: libdl is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([SQLWriteDSNToIni],[odbcinst iodbcinst],[],[
	echo "Error: ODBC is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([SQLConnect],[odbc iodbc],[], [
	echo "Error: ODBC is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([cryptInit], [cl],[],[
	echo "Error: cryptlib is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([X509_VERIFY_PARAM_free], [crypto],[],[
	echo "Error: openSSL is required for building this project"
	exit -1;
])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h memory.h my_global.h mysql.h netdb.h netinet/in.h semaphore.h stdbool.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h syslog.h termios.h unistd.h wchar.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_GETPGRP
AC_PROG_GCC_TRADITIONAL
#AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
#AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm bzero dup2 getcwd gethostbyaddr gethostbyname gethostname getpass memmove memset mkdir mysql_real_connect munmap select socket strcasecmp strchr strdup strerror strncasecmp strpbrk strrchr strstr strtol strtoul strtoull])

AC_CONFIG_FILES([Makefile
                 cg/Makefile
                 cg/asn/Makefile
                 cg/asn_gen/Makefile
                 cg/casn/Makefile
                 cg/tools/Makefile
                 proto/Makefile
                 roa-lib/Makefile
                 roa-utils/Makefile
                 rsync_aur/Makefile
                 rtr/Makefile
                 subsystemTests/Makefile
                 subsystemTests/rtr/Makefile
                 testcases/Makefile
                 testbed/Makefile
                 testbed/src/Makefile
                 utils/Makefile
                 utils/tests/Makefile
                 utils/mysql-c-api/Makefile
])
AC_OUTPUT
