#ifndef _LIB_UTIL_PATH_COMPAT_H
#define _LIB_UTIL_PATH_COMPAT_H

#include <limits.h>
#include <stdlib.h>

#ifdef __NetBSD__

// NetBSD's realpath(3) doesn't appear to be POSIX-compliant.
// It doesn't allocate a resolved_path if the parameter is NULL.
char * realpath_compat(
    const char *path,
    char *resolved_path);

#ifndef PATH_COMPAT_NO_CLOBBER
#define realpath realpath_compat
#endif

#endif

#endif
