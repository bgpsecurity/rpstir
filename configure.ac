#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([rpstir], [0.14], [rpstir-support@bbn.com])
PACKAGE_LONGNAME="Relying Party Security Technology for Internet Routing"
AC_SUBST([PACKAGE_LONGNAME])
PACKAGE_NAME_UC="RPSTIR"
AC_SUBST([PACKAGE_NAME_UC])
AC_DEFINE_UNQUOTED([PACKAGE_NAME_UC], ["$PACKAGE_NAME_UC"])
CONFIG_ENV_VAR="RPSTIR_CONFIG"
AC_SUBST([CONFIG_ENV_VAR])
AC_DEFINE_UNQUOTED([CONFIG_ENV_VAR], ["$CONFIG_ENV_VAR"])
AC_CONFIG_AUX_DIR([build-aux])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
# if this is bumped to 1.12 or later, remove build-aux/tap-driver.sh
# from the repository.  automake 1.12+ comes with tap-driver.sh, and
# autoreconf will copy in the version distributed with automake.
# (automake 1.11 and older don't come with tap-driver.sh, so
# build-aux/tap-driver.sh is checked in to keep the above
# AC_REQUIRE_AUX_FILE line from causing configure to complain about a
# mising file if the user has automake 1.11.)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
# The following would default to silent, but depends on GNU make behavior.
# AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([bin/asn1/rr.c])
AC_CONFIG_MACRO_DIR([m4])

# for tap-driver.sh
AC_PROG_AWK

AC_PATH_PROG([GIT], [git])
AC_MSG_CHECKING([for extra version information])
AS_IF([test "x${GIT}" != x && test -x "${GIT}" && test -d "${srcdir}/.git"], [
    PACKAGE_VERSION_FULL="$(
      cd "${srcdir}" &&
      ${GIT} describe --tags --long --always --dirty)"
    AS_IF([test -n "$PACKAGE_VERSION_FULL"], [
        AC_MSG_RESULT([$PACKAGE_VERSION_FULL])
      ], [
        PACKAGE_VERSION_FULL="$PACKAGE_VERSION"
        AC_MSG_RESULT([failed])
      ])
  ], [
    PACKAGE_VERSION_FULL="$PACKAGE_VERSION"
    AC_MSG_RESULT([no])
  ])
AC_SUBST([PACKAGE_VERSION_FULL])
AC_DEFINE_UNQUOTED([PACKAGE_VERSION_FULL], ["$PACKAGE_VERSION_FULL"])

MIN_OPENSSL_VERSION="1.0.1g"
MIN_MYSQL_VERSION="5.1"
MIN_MYSQL_ODBC_VERSION="3.51"
MIN_RSYNC_VERSION="2.6.9"
MIN_PYTHON_VERSION="2.7"
AC_SUBST([MIN_OPENSSL_VERSION])
AC_SUBST([MIN_MYSQL_VERSION])
AC_SUBST([MIN_MYSQL_ODBC_VERSION])
AC_SUBST([MIN_RSYNC_VERSION])
AC_SUBST([MIN_PYTHON_VERSION])

AM_MAINTAINER_MODE
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
AS_IF([test -z "$SHELL_BASH"], [
    AC_MSG_WARN([cannot find bash, which is needed by some scripts])
  ])

# RPSTIR_SEARCH_LIBS is a wrapper around AC_SEARCH_LIBS to make it
# easier to put the -l<library> flag in a variable other than LIBS.
# Arguments:
#   1. function:  same as in AC_SEARCH_LIBS
#   2. search-libs:  same as in AC_SEARCH_LIBS
#   3. [prefix]:  rather than prepend -l<library> to LIBS as in
#      AC_SEARCH_LIBS, this macro prepends to prefixLIBS.  Defaults to
#      "CONFIGURE_".
#   4. [ignored-flag]:  if the -l<library> flag to prepend to
#      prefixLIBS matches this shell 'case' statement pattern, the
#      flag is not prepended
#   5. [action-if-found]:  same as in AC_SEARCH_LIBS
#   6. [action-if-not-found]:  same as in AC_SEARCH_LIBS
#   7. [other-libraries]:  same as in AC_SEARCH_LIBS
AC_DEFUN([RPSTIR_SEARCH_LIBS], [
    # RPSTIR_SEARCH_LIBS
    rpstir_save_LIBS=${LIBS}
    AC_SEARCH_LIBS([$1], [$2], [
        AS_VAR_PUSHDEF([rpstir_LIBS],
          [m4_default([$3], [[CONFIGURE_]])LIBS])
        AS_CASE([${ac_cv_search_$1}],
          [no|""], [AC_MSG_FAILURE([assertion error])],
          ["none required"|m4_default([$4], [""])], [],
          [
            AS_VAR_COPY([rpstir_tmp], [rpstir_LIBS])
            AS_VAR_SET([rpstir_LIBS], ["${ac_cv_search_$1} ${rpstir_tmp}"])
          ])
        AS_VAR_POPDEF([rpstir_LIBS])
        $5
      ], [$6], [$7])
    LIBS=${rpstir_save_LIBS}
  ])

######################################################################
# The following are helper macros to back up and restore user flag
# variables.  User flag variables should only be temporarily modified;
# their values should be backed up before executing a check that
# modifies their value and restored after the check completes.  This
# is important for the following reasons:
#
#   * These variables are AC_SUBSTed into Makefile.in.  If the value
#     substituted into Makefile.in differs from what the user set, the
#     user is unable to safely override them when running 'make'.
#     See:
#     https://www.gnu.org/software/automake/manual/html_node/User-Variables.html
#     https://www.gnu.org/software/autoconf/manual/html_node/Preset-Output-Variables.html#index-CFLAGS-84
#
#   * Modifying them can interfere with subsequent checks.
#
# A common usage pattern for these macros is:
#
#   * Use flags_backup only once at the beginning
#
#   * For each library dependency, run
#     flags_declare_addons([[NAME_]]), substituting an appropriate
#     name for NAME_.  For example, for OpenSSL, run
#     flags_declare_addons([[OPENSSL_]]).
#
#   * For each check that modifies a user flag variable:
#     - Run the check
#     - For each flag variable foo, set NAME_foo to the flags that the
#       check determined should be added to foo.  For example, if
#       linking against OpenSSL requires adding -lcrypto to LIBS, then
#       set OPENSSL_LIBS to -lcrypto
#     - Use flags_restore to restore the backed up flags so that the
#       next check (or AC_OUTPUT) has unmodified flags
#
#   * If a check depends on a library, and that library's flags were
#     saved under NAME_, use flags_load_addons([[NAME_]]) before
#     running the check to append that library's flags to the user
#     flag variables.

# List of user flag variables used in this configure.ac.
m4_define([flagvars], [[CPPFLAGS] [CFLAGS] [LIBS] [LDFLAGS]])

# Back up user flag variables:  For each user flag variable foo, set
# the foo_BACKUP variable to the value of foo.
m4_define([flags_backup], [
    m4_foreach_w([flagvar], flagvars, [
        flagvar[_BACKUP=${]flagvar[}]
      ])
  ])

# Restore user flag variables:  For each user flag variable foo, set
# its value to the value of the foo_BACKUP variable.
m4_define([flags_restore], [
    m4_foreach_w([flagvar], flagvars, [
        flagvar[=${]flagvar[_BACKUP}]
      ])
  ])

# For each user flag variable foo, append the value of the PREFIXfoo
# variable (except prepend when foo is LIBS), where PREFIX is the
# first argument passed to the macro.  If two arguments are passed to
# the macro, append (or prepend) to $2foo instead of foo.
m4_define([flags_load_addons], [
    m4_foreach_w([flagvar], flagvars, [
        m4_if(flagvar, [LIBS], [
            $2[]flagvar[="${]$1[]flagvar[} ${]$2[]flagvar[}"]
          ], [
            $2[]flagvar[="${]$2[]flagvar[} ${]$1[]flagvar[}"]
          ])
      ])
  ])

# For each user variable foo, unset PREFIXfoo and mark PREFIXfoo for
# substitution where where PREFIX is the first argument passed to the
# macro.
m4_define([flags_declare_addons], [
    m4_foreach_w([flagvar], flagvars, [
        AS_UNSET($1[]flagvar)
        AC_SUBST($1[]flagvar)
      ])
  ])
######################################################################

flags_backup

# these flag addon variables hold flags that should be used
# everywhere, not just for particular programs and libraries
flags_declare_addons([[CONFIGURE_]])

######################################################################
# MySQL
######################################################################
flags_declare_addons([[MYSQL_]])
AC_ARG_WITH(
  [mysql-config],
  [AS_HELP_STRING([--with-mysql-config], [Path to mysql_config executable])],
  [mysql_config=$withval],
  [mysql_config=mysql_config])
AC_PATH_PROG([MYSQL_CONFIG], [${mysql_config}])
AS_IF([test "x${MYSQL_CONFIG}" != x && test -x "${MYSQL_CONFIG}"], [
    MYSQL_CPPFLAGS=$("$MYSQL_CONFIG" --include)

    # this is a bit of a hack because mysql_config --libs_r specifies
    # compiler flags, not linker flags
    for flag in $("$MYSQL_CONFIG" --libs_r); do
      AS_CASE([$flag],
        [-L*], [
          libpath=${flag#-L}
          MYSQL_LDFLAGS="${MYSQL_LDFLAGS} -L${libpath}\
 -Wl,-rpath -Wl,${libpath}"
        ],
        [-l*], [MYSQL_LIBS="${MYSQL_LIBS} ${flag}"],
        [])
    done
  ], [
    AC_MSG_ERROR([cannot find or execute mysql_config,\
 make sure MySQL client is installed])
  ])
AC_MSG_CHECKING([whether mysql flags are useable])
flags_load_addons([[MYSQL_]])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[]], [[return 0;]])],
  [AC_MSG_RESULT([yes])],
  [
    AC_MSG_RESULT([no])
    AC_MSG_FAILURE([cannot compile and link a program with the flags\
 supplied by mysql_config])
  ])
flags_restore

######################################################################
# libdl
######################################################################
flags_declare_addons([[LIBDL_]])
RPSTIR_SEARCH_LIBS([dlopen], [dl], [LIBDL_], [], [], [
    AC_MSG_ERROR([libdl is required for building this project])
  ])

######################################################################
# ODBC
######################################################################
flags_declare_addons([[ODBC_]])
AC_ARG_WITH(
  [odbc-include],
  [AS_HELP_STRING(
    [--with-odbc-include],
    [Path to odbc include files: Defaults to /usr/local/include])],
  [odbc_include=$withval],
  [odbc_include=/usr/local/include])
AS_IF([test x${odbc_include} != x], [ODBC_CPPFLAGS="-I${odbc_include}"])
AC_ARG_WITH(
  [odbc-lib],
  [AS_HELP_STRING(
    [--with-odbc-lib],
    [Path to odbc install location: Defaults to /usr/local/lib])],
  [odbc_lib=$withval],
  [odbc_lib=/usr/local/lib])
AS_IF([test x${odbc_lib} != x], [
    ODBC_LDFLAGS="-L${odbc_lib} -Wl,-rpath -Wl,${odbc_lib}"
  ])
flags_load_addons([[ODBC_]])
RPSTIR_SEARCH_LIBS([SQLWriteDSNToIni], [odbcinst iodbcinst], [ODBC_], [], [], [
    AC_MSG_ERROR([ODBC is required for building this project])
  ])
flags_restore
flags_load_addons([[ODBC_]])
RPSTIR_SEARCH_LIBS([SQLConnect], [odbc iodbc], [ODBC_], [], [], [
    AC_MSG_ERROR([ODBC is required for building this project])
  ])
flags_restore

######################################################################
# cryptlib
######################################################################
flags_declare_addons([[CRYPTLIB_]])
AC_ARG_WITH(
  [cryptlib-include],
  [AS_HELP_STRING(
    [--with-cryptlib-include],
    [Path to cryptlib install location: Defaults to /usr/local/include])],
  [cryptlib_include=$withval],
  [cryptlib_include=/usr/local/include])
AS_IF([test x${cryptlib_include} != x], [
    CRYPTLIB_CPPFLAGS="-I${cryptlib_include}"
  ])
AC_ARG_WITH(
  [cryptlib-lib],
  [AS_HELP_STRING(
    [--with-cryptlib-lib],
    [Path to cryptlib install location: Defaults to /usr/local/lib])],
  [cryptlib_lib=$withval],
  [cryptlib_lib=/usr/local/lib])
AS_IF([test x${cryptlib_lib} != x], [
    CRYPTLIB_LDFLAGS="-L${cryptlib_lib} -Wl,-rpath -Wl,${cryptlib_lib}"
  ])
flags_load_addons([[CRYPTLIB_]])
RPSTIR_SEARCH_LIBS([cryptInit], [cl], [CRYPTLIB_], [], [], [
    AC_MSG_ERROR([cryptlib is required for building this project])
  ])
flags_restore

######################################################################
# OpenSSL
######################################################################
flags_declare_addons([[OPENSSL_]])
AC_ARG_WITH(
  [ssl-include],
  [AS_HELP_STRING(
    [--with-ssl-include],
    [Path to OpenSSL library install location: Defaults to
     /usr/local/ssl/include])],
  [ssl_include=$withval],
  [ssl_include=/usr/local/ssl/include])
AS_IF([test x${ssl_include} != x], [OPENSSL_CPPFLAGS="-I${ssl_include}"])
AC_ARG_WITH(
  [ssl-lib],
  [AS_HELP_STRING(
    [--with-ssl-lib],
    [Path to OpenSSL library install location: Defaults to
     /usr/local/ssl/lib])],
  [ssl_lib=$withval],
  [ssl_lib=/usr/local/ssl/lib])
AS_IF([test x${ssl_lib} != x], [
    OPENSSL_LDFLAGS="-L${ssl_lib} -Wl,-rpath -Wl,${ssl_lib}"
  ])
flags_load_addons([[LIBDL_]])
flags_load_addons([[OPENSSL_]])
RPSTIR_SEARCH_LIBS([X509_VERIFY_PARAM_free], [crypto], [OPENSSL_], [], [], [
    AC_MSG_ERROR([OpenSSL is required for building this project])
  ])
flags_restore
flags_load_addons([[LIBDL_]])
flags_load_addons([[OPENSSL_]])
RPSTIR_SEARCH_LIBS([v3_addr_validate_path], [crypto], [OPENSSL_],
  ["${ac_cv_search_X509_VERIFY_PARAM_free}"], [], [
    AC_MSG_ERROR([OpenSSL with RFC 3779 is required for building this project])
  ])
flags_restore

# add all of the library-specific flags to the CONFIGURE_* flags
#
# TODO: delete this and instead reference the library-specific flag
# variables from the appropriate *_LDFLAGS, *_LIBADD, *_LDADD,
# *_CPPFLAGS variables in Makefile.am
m4_foreach_w([lib], [[MYSQL] [LIBDL] [ODBC] [CRYPTLIB] [OPENSSL]], [
    flags_load_addons([lib[_]], [[CONFIGURE_]])
  ])

#Check for GCC Stack-Smashing Protector and enable in some cases
#  If --enable-stack-protector is specified: enable it
#  Else if --disable-stack-protector is specified: don't enable it
#  Else if C compiler supports it: enable it
#  Else: don't enable it
AC_MSG_CHECKING([whether C compiler supports -fstack-protector])
CFLAGS="${CFLAGS} -fstack-protector"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
  [AC_MSG_RESULT([yes]); HAVE_STACK_PROTECTOR=yes],
  [AC_MSG_RESULT([no]);  HAVE_STACK_PROTECTOR=no])
flags_restore
AC_ARG_ENABLE(
  [stack-protector],
  [AS_HELP_STRING(
    [--enable-stack-protector],
    [Whether or not to add -fstack-protector to CFLAGS: Defaults
     to yes when using gcc and no otherwise])],
  [
    AS_IF([test x"$enableval" != xno], [
        CONFIGURE_CFLAGS="${CONFIGURE_CFLAGS} -fstack-protector"
      ])
  ],
  [
    AS_IF([test x"$HAVE_STACK_PROTECTOR" = xyes], [
        CONFIGURE_CFLAGS="${CONFIGURE_CFLAGS} -fstack-protector"
      ])
  ])

#Check for pthreads.
AX_PTHREAD
AS_IF([test x"$ax_pthread_ok" != xyes], [
    AC_MSG_ERROR([pthread support is required])
  ])
CONFIGURE_LIBS="$PTHREAD_LIBS $CONFIGURE_LIBS"
CONFIGURE_CFLAGS="$CONFIGURE_CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

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
AS_IF([test "$ac_cv_func_getline" != yes], [
    AC_MSG_ERROR([The getline() function from POSIX 2008 is required.])
  ])


AC_CONFIG_FILES([
    Makefile
    README
  ])

AC_CONFIG_LINKS([lib/rpki-asn1/casn.h:lib/casn/casn.h])

AC_OUTPUT
