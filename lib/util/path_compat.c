#include <errno.h>

#define PATH_COMPAT_NO_CLOBBER
#include "path_compat.h"
#undef PATH_COMPAT_NO_CLOBBER


#ifdef __NetBSD__

#include <sys/param.h>

char * realpath_compat(
    const char *path,
    char *resolved_path)
{
    if (resolved_path != NULL)
    {
        // just assume resolved_path is large enough,
        // since we don't know its size
        return realpath(path, resolved_path);
    }
    else
    {
        resolved_path = malloc(MAXPATHLEN);
        if (resolved_path == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }

        if (realpath(path, resolved_path) == NULL)
        {
            // preserve realpath()'s errno
            int errno_save = errno;
            free(resolved_path);
            errno = errno_save;
            return NULL;
        }

        return resolved_path;
    }
}

#endif
