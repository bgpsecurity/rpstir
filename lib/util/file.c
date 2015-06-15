#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>

#include "file.h"

bool mkdir_recursive(
    const char *pathname,
    mode_t mode)
{
    if (pathname == NULL)
    {
        errno = EINVAL;
        return false;
    }

    if (mkdir(pathname, mode) == 0)
    {
        return true;
    }

    if (errno == EEXIST)
    {
        struct stat pathname_stat;
        if (stat(pathname, &pathname_stat) != 0)
        {
            // errno was set by stat()
            return false;
        }
        if (S_ISDIR(pathname_stat.st_mode))
        {
            return true;
        }
        else
        {
            errno = EEXIST;
            return false;
        }
    }
    else if (errno == ENOENT)
    {
        char * dirname_base = strdup(pathname);
        if (dirname_base == NULL)
        {
            errno = ENOMEM;
            return false;
        }
        char * dir = dirname(dirname_base);
        if (strcmp(dir, pathname) == 0)
        {
            // avoid unbounded recursion
            free(dirname_base);
            // not the best error, but this shouldn't happen anyway
            errno = ENOENT;
            return false;
        }
        if (!mkdir_recursive(dir, mode))
        {
            free(dirname_base);
            // errno was set by mkdir_recursive()
            return false;
        }
        free(dirname_base);
        return mkdir(pathname, mode) == 0;
    }
    else
    {
        // errno was set by mkdir()
        return false;
    }
}
