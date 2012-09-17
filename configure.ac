#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(rpstir, 0.4, rpstir-support@bbn.com)
PACKAGE_LONGNAME="Relying Party Security Technology for Internet Routing"
AC_SUBST([PACKAGE_LONGNAME])
PACKAGE_NAME_UC="RPSTIR"
AC_SUBST([PACKAGE_NAME_UC])
AC_DEFINE_UNQUOTED([PACKAGE_NAME_UC], ["$PACKAGE_NAME_UC"])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
# The following would default to silent, but depends on GNU make behavior.
# AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([bin/asn1/rr.c])
AC_CONFIG_MACRO_DIR([m4])

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
AM_PATH_PYTHON([2.6])

# Ideally this should be a check for how to create a temporary file on each platform,
# but this seems to work for now on multiple platforms.
MKTEMP="mktemp -t tmp.XXXXXXXXXX"
AC_SUBST([MKTEMP])

AC_PATH_PROG([SHELL_BASH], [bash])
if test -z "$SHELL_BASH"; then
  AC_MSG_WARN([cannot find bash, which is needed by some scripts])
fi


AC_ARG_WITH(
    [ssl-include],
    AS_HELP_STRING([--with-ssl-include],[Path to OpenSSL library install location: Defaults to /usr/local/ssl/include ]),
    [ ssl_include=$withval],
    [ ssl_include=/usr/local/ssl/include]
)

AC_ARG_WITH(
    [ssl-lib],
    AS_HELP_STRING([--with-ssl-lib],[Path to OpenSSL library install location: Defaults to /usr/local/ssl/lib ]),
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
  mysql_config_LIBS=""
  for flag in `$MYSQL_CONFIG --libs_r`; do
    case $flag in
      -L*)
        libpath="`echo $flag | $SED 's/^-L//'`"
        LDFLAGS="-L${libpath} -Wl,-rpath -Wl,${libpath} ${LDFLAGS}"
        ;;
      -l*)
        mysql_config_LIBS="${mysql_config_LIBS} ${flag}"
        ;;
      *)
        ;;
    esac
  done
  LIBS="${mysql_config_LIBS} ${LIBS}"
else
  AC_MSG_ERROR([cannot find or execute mysql_config, make sure MySQL client is installed])
fi

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

#Check for pthreads.
AX_PTHREAD
if test x"$ax_pthread_ok" != xyes; then
	AC_MSG_ERROR([pthread support is required])
fi
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

#Checks for libraries.
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
	echo "Error: OpenSSL is required for building this project"
	exit -1;
])
AC_SEARCH_LIBS([v3_addr_validate_path], [crypto],[],[
	echo "Error: OpenSSL with RFC 3779 is required for building this project"
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
AC_CHECK_FUNCS([alarm bzero dup2 getcwd gethostbyaddr gethostbyname gethostname getpass memmove memset mkdir mysql_real_connect munmap select sem_timedwait socket strcasecmp strchr strdup strerror strncasecmp strpbrk strrchr strstr strtol strtoul strtoull])

# warn if the target isn't 32-bit
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([void *])
if test "$ac_cv_sizeof_int" != 4 -o "$ac_cv_sizeof_long" != 4 -o "$ac_cv_sizeof_void_p" != 4; then
	AC_MSG_WARN([currently only 32-bit targets are supported])
fi


AC_CONFIG_FILES([
    etc/envir.setup
    Makefile
    tests/test.include
    INSTRUCTIONS
])

AC_CONFIG_FILES([bin/rpki/chaser.sh],
                [chmod +x bin/rpki/chaser.sh])

AC_CONFIG_FILES([bin/rpki/results.py],
                [chmod +x bin/rpki/results.py])

AC_CONFIG_FILES([bin/rpki/run_from_TALs.sh],
                [chmod +x bin/rpki/run_from_TALs.sh])

AC_CONFIG_FILES([bin/rpki/updateTA.py],
                [chmod +x bin/rpki/updateTA.py])

AC_CONFIG_FILES([bin/rpki-rsync/rsync_cord.py],
                [chmod +x bin/rpki-rsync/rsync_cord.py])

AC_CONFIG_FILES([tests/subsystem/rtr/badPDUs.py],
                [chmod +x tests/subsystem/rtr/badPDUs.py])

AC_CONFIG_FILES([tests/subsystem/rtr/test.sh],
                [chmod +x tests/subsystem/rtr/test.sh])

AC_CONFIG_FILES([tests/subsystem/initDB],
                [chmod +x tests/subsystem/initDB])

AC_CONFIG_FILES([tests/subsystem/rpki-local-ta/initDB4],
                [chmod +x tests/subsystem/rpki-local-ta/initDB4])

AC_CONFIG_FILES([tests/subsystem/runSubsystemTest.sh],
                [chmod +x tests/subsystem/runSubsystemTest.sh])

AC_CONFIG_FILES([tests/subsystem/rpki-local-ta/runSubsystemTest4.sh],
                [chmod +x tests/subsystem/rpki-local-ta/runSubsystemTest4.sh])

AC_CONFIG_FILES([tests/subsystem/step1.1],
                [chmod +x tests/subsystem/step1.1])

AC_CONFIG_FILES([tests/subsystem/step1.2],
                [chmod +x tests/subsystem/step1.2])

AC_CONFIG_FILES([tests/subsystem/step1.3],
                [chmod +x tests/subsystem/step1.3])

AC_CONFIG_FILES([tests/subsystem/step1.4],
                [chmod +x tests/subsystem/step1.4])

AC_CONFIG_FILES([tests/subsystem/step1.5],
                [chmod +x tests/subsystem/step1.5])

AC_CONFIG_FILES([tests/subsystem/step1.6],
                [chmod +x tests/subsystem/step1.6])

AC_CONFIG_FILES([tests/subsystem/step1.7],
                [chmod +x tests/subsystem/step1.7])

AC_CONFIG_FILES([tests/subsystem/step1.8],
                [chmod +x tests/subsystem/step1.8])

AC_CONFIG_FILES([tests/subsystem/step1.9],
                [chmod +x tests/subsystem/step1.9])

AC_CONFIG_FILES([tests/subsystem/step2.1],
                [chmod +x tests/subsystem/step2.1])

AC_CONFIG_FILES([tests/subsystem/step2.2],
                [chmod +x tests/subsystem/step2.2])

AC_CONFIG_FILES([tests/subsystem/step2.3],
                [chmod +x tests/subsystem/step2.3])

AC_CONFIG_FILES([tests/subsystem/step2.4],
                [chmod +x tests/subsystem/step2.4])

AC_CONFIG_FILES([tests/subsystem/step2.5],
                [chmod +x tests/subsystem/step2.5])

AC_CONFIG_FILES([tests/subsystem/step2.6],
                [chmod +x tests/subsystem/step2.6])

AC_CONFIG_FILES([tests/subsystem/step2.7],
                [chmod +x tests/subsystem/step2.7])

AC_CONFIG_FILES([tests/subsystem/step2.8],
                [chmod +x tests/subsystem/step2.8])

AC_CONFIG_FILES([tests/subsystem/step3.1],
                [chmod +x tests/subsystem/step3.1])

AC_CONFIG_FILES([tests/subsystem/step3.2],
                [chmod +x tests/subsystem/step3.2])

AC_CONFIG_FILES([tests/subsystem/step3.3],
                [chmod +x tests/subsystem/step3.3])

AC_CONFIG_FILES([tests/subsystem/step3.4],
                [chmod +x tests/subsystem/step3.4])

AC_CONFIG_FILES([tests/subsystem/step3.5],
                [chmod +x tests/subsystem/step3.5])

AC_CONFIG_FILES([tests/subsystem/step3.6],
                [chmod +x tests/subsystem/step3.6])

AC_CONFIG_FILES([tests/subsystem/step3.7],
                [chmod +x tests/subsystem/step3.7])

AC_CONFIG_FILES([tests/subsystem/step3.8],
                [chmod +x tests/subsystem/step3.8])

AC_CONFIG_FILES([tests/subsystem/step3.9],
                [chmod +x tests/subsystem/step3.9])

AC_CONFIG_FILES([tests/subsystem/rpki-local-ta/step4],
                [chmod +x tests/subsystem/rpki-local-ta/step4])

AC_CONFIG_FILES([tests/system/testbed/src/create_objects.py],
                [chmod +x tests/system/testbed/src/create_objects.py])

AC_CONFIG_FILES([tests/system/testbed/src/generic_allocate.py],
                [chmod +x tests/system/testbed/src/generic_allocate.py])

AC_CONFIG_FILES([tests/system/testbed/src/rpkirepo.py],
                [chmod +x tests/system/testbed/src/rpkirepo.py])

AC_CONFIG_FILES([tests/system/testbed/src/testbed_create.py],
                [chmod +x tests/system/testbed/src/testbed_create.py])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all.sh],
                [chmod +x tests/conformance/scripts/gen_all.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all_CMSs.sh],
                [chmod +x tests/conformance/scripts/gen_all_CMSs.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all_CRLs.sh],
                [chmod +x tests/conformance/scripts/gen_all_CRLs.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all_MFTs.sh],
                [chmod +x tests/conformance/scripts/gen_all_MFTs.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all_ROAs.sh],
                [chmod +x tests/conformance/scripts/gen_all_ROAs.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_all_certs.sh],
                [chmod +x tests/conformance/scripts/gen_all_certs.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_child_ca.sh],
                [chmod +x tests/conformance/scripts/gen_child_ca.sh])

AC_CONFIG_FILES([tests/conformance/scripts/gen_mft.sh],
                [chmod +x tests/conformance/scripts/gen_mft.sh])

AC_CONFIG_FILES([tests/conformance/scripts/make_test_CMS.sh],
                [chmod +x tests/conformance/scripts/make_test_CMS.sh])

AC_CONFIG_FILES([tests/conformance/scripts/make_test_CRL.sh],
                [chmod +x tests/conformance/scripts/make_test_CRL.sh])

AC_CONFIG_FILES([tests/conformance/scripts/make_test_MFT.sh],
                [chmod +x tests/conformance/scripts/make_test_MFT.sh])

AC_CONFIG_FILES([tests/conformance/scripts/make_test_cert.sh],
                [chmod +x tests/conformance/scripts/make_test_cert.sh])

AC_CONFIG_FILES([tests/subsystem/testcases/tools/create_cert.py],
                [chmod +x tests/subsystem/testcases/tools/create_cert.py])

AC_CONFIG_FILES([tests/subsystem/testcases/tools/run_tc.py],
                [chmod +x tests/subsystem/testcases/tools/run_tc.py])

AC_CONFIG_LINKS([lib/rpki-asn1/casn.h:lib/casn/casn.h])

AC_OUTPUT
