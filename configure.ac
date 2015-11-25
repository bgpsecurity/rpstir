#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([rpstir], [0.11], [rpstir-support@bbn.com])
PACKAGE_LONGNAME="Relying Party Security Technology for Internet Routing"
AC_SUBST([PACKAGE_LONGNAME])
PACKAGE_NAME_UC="RPSTIR"
AC_SUBST([PACKAGE_NAME_UC])
AC_DEFINE_UNQUOTED([PACKAGE_NAME_UC], ["$PACKAGE_NAME_UC"])
CONFIG_ENV_VAR="RPSTIR_CONFIG"
AC_SUBST([CONFIG_ENV_VAR])
AC_DEFINE_UNQUOTED([CONFIG_ENV_VAR], ["$CONFIG_ENV_VAR"])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
# The following would default to silent, but depends on GNU make behavior.
# AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([bin/asn1/rr.c])
AC_CONFIG_MACRO_DIR([m4])

AC_PATH_PROG([GIT], [git])
AC_MSG_CHECKING([for extra version information])
if test "x${GIT}" != x && test -x "${GIT}" && test -d "${srcdir}/.git"; then
    PACKAGE_VERSION_FULL="$(
        cd "${srcdir}" &&
        ${GIT} describe --tags --long --always --dirty)"
    if test -n "$PACKAGE_VERSION_FULL"; then
        AC_MSG_RESULT([$PACKAGE_VERSION_FULL])
    else
        PACKAGE_VERSION_FULL="$PACKAGE_VERSION"
        AC_MSG_RESULT([failed])
    fi
else
    PACKAGE_VERSION_FULL="$PACKAGE_VERSION"
    AC_MSG_RESULT([no])
fi
AC_SUBST([PACKAGE_VERSION_FULL])
AC_DEFINE_UNQUOTED([PACKAGE_VERSION_FULL], ["$PACKAGE_VERSION_FULL"])

MIN_PYTHON_VERSION="2.7"

AM_MAINTAINER_MODE
: ${CFLAGS=""}
# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AS_IF([test "x${ac_cv_prog_cc_c99}" = xno],
      [AC_MSG_ERROR([C99 compiler is required])])
AM_PROG_CC_C_O
AC_PROG_RANLIB
AC_PROG_SED
AM_PATH_PYTHON([$MIN_PYTHON_VERSION])
AC_PROG_LN_S

# Ideally this should be a check for how to create a temporary file on
# each platform, but this seems to work for now on multiple platforms.
MKTEMP="mktemp -t tmp.XXXXXXXXXX"
MKTEMP_DIR="mktemp -t tmp.XXXXXXXXXX -d"
AC_SUBST([MKTEMP])
AC_SUBST([MKTEMP_DIR])

AC_PATH_PROG([SHELL_BASH], [bash])
if test -z "$SHELL_BASH"; then
  AC_MSG_WARN([cannot find bash, which is needed by some scripts])
fi


AC_ARG_WITH(
    [ssl-include],
    [AS_HELP_STRING(
        [--with-ssl-include],
        [Path to OpenSSL library install location: Defaults to
         /usr/local/ssl/include])],
    [ ssl_include=$withval],
    [ ssl_include=/usr/local/ssl/include]
)

AC_ARG_WITH(
    [ssl-lib],
    [AS_HELP_STRING(
        [--with-ssl-lib],
        [Path to OpenSSL library install location: Defaults to
         /usr/local/ssl/lib])],
    [ ssl_lib=$withval],
    [ ssl_lib=/usr/local/ssl/lib]
)

AC_ARG_WITH(
    [cryptlib-include],
    [AS_HELP_STRING(
        [--with-cryptlib-include],
        [Path to cryptlib install location: Defaults to /usr/local/include])],
    [ cryptlib_include=$withval],
    [ cryptlib_include=/usr/local/include]
)

AC_ARG_WITH(
    [odbc-include],
    [AS_HELP_STRING(
        [--with-odbc-include],
        [Path to odbc include files: Defaults to /usr/local/include])],
    [ odbc_include=$withval],
    [ odbc_include=/usr/local/include]
)

AC_ARG_WITH(
    [cryptlib-lib],
    [AS_HELP_STRING(
        [--with-cryptlib-lib],
        [Path to cryptlib install location: Defaults to /usr/local/lib])],
    [ cryptlib_lib=$withval],
    [ cryptlib_lib=/usr/local/lib]
)

AC_ARG_WITH(
    [odbc-lib],
    [AS_HELP_STRING(
        [--with-odbc-lib],
        [Path to odbc install location: Defaults to /usr/local/lib])],
    [ odbc_lib=$withval],
    [ odbc_lib=/usr/local/lib]
)

AC_ARG_WITH(
    [mysql-config],
    [AS_HELP_STRING([--with-mysql-config],[Path to mysql_config executable ])],
    [ mysql_config=$withval],
    [ mysql_config=mysql_config]
)

AC_PATH_PROG([MYSQL_CONFIG], [${mysql_config}])
if test "x${MYSQL_CONFIG}" != x && test -x "${MYSQL_CONFIG}"; then
  # this is a bit of a hack because mysql_config --include specified
  # non-system include flags
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

  # this is a bit of a hack because mysql_config --libs_r specifies
  # compiler flags, not linker flags
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
  AC_MSG_ERROR(
    [cannot find or execute mysql_config, make sure MySQL client is installed])
fi
AC_MSG_CHECKING([whether mysql flags are useable])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[]],
        [[return 0;]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no]); AC_MSG_FAILURE([cannot compile and link a program with the flags supplied by mysql_config])])

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
    [AS_HELP_STRING(
        [--enable-stack-protector],
        [Whether or not to add -fstack-protector to CFLAGS: Defaults
         to yes when using gcc and no otherwise])],
    [
        if test x"$enableval" != xno; then
            CFLAGS="${CFLAGS-} -fstack-protector"
        fi
    ],
    [
        if test x"$HAVE_STACK_PROTECTOR" = xyes; then
            CFLAGS="${CFLAGS-} -fstack-protector"
        fi
    ]
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
    AC_MSG_ERROR([libdl is required for building this project])
])
AC_SEARCH_LIBS([SQLWriteDSNToIni],[odbcinst iodbcinst],[],[
    AC_MSG_ERROR([ODBC is required for building this project])
])
AC_SEARCH_LIBS([SQLConnect],[odbc iodbc],[], [
    AC_MSG_ERROR([ODBC is required for building this project])
])
AC_SEARCH_LIBS([cryptInit], [cl],[],[
    AC_MSG_ERROR([cryptlib is required for building this project])
])
AC_SEARCH_LIBS([X509_VERIFY_PARAM_free], [crypto],[],[
    AC_MSG_ERROR([OpenSSL is required for building this project])
])
AC_SEARCH_LIBS([v3_addr_validate_path], [crypto],[],[
    AC_MSG_ERROR([OpenSSL with RFC 3779 is required for building this project])
])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime getline sem_timedwait])
if test "$ac_cv_func_getline" != yes; then
    AC_MSG_ERROR([The getline() function from POSIX 2008 is required.])
fi


AC_CONFIG_FILES([
    Makefile
])

AC_CONFIG_LINKS([lib/rpki-asn1/casn.h:lib/casn/casn.h])

AC_OUTPUT
