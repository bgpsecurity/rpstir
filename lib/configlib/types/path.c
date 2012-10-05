#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>

#include "util/path_compat.h"

#include "path.h"


/**
    Try to do as much realpath() normalization as possible, given that the
    speified path may or may not exist.

    @return Normalized path, or NULL on error.
 */
static char * realpath_noent(
    const struct config_context * context,
    const char *path)
{
    // These variables store the current separation of path into (possibly
    // extant) dir and non-existant base.
    //
    // Loop invariant:
    //   If base is NULL: dir == path
    //   Else dir/base == path
    char * dir = strdup(path);
    char * base = NULL;

    if (dir == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return NULL;
    }

    // Loop local variables. These variables should all be treated as undefined
    // at the beginning of each iteration of the loop.
    char * dir_normalized;
    char * copy_for_dirname;
    char * copy_for_basename;
    char * dir_dirname;
    char * dir_basename;
    char * tmp;
    size_t length;

    while (true)
    {
        dir_normalized = realpath(dir, NULL);
        if (dir_normalized != NULL)
        {
            // We're done, just patch dir_normalized and base together and
            // return that.

            free(dir);

            if (base == NULL)
            {
                return dir_normalized;
            }
            else
            {
                dir_normalized = realloc(dir_normalized,
                                         strlen(dir_normalized) +
                                         1 /* '/' */+
                                         strlen(base) +
                                         1 /* null terminator */);
                if (dir_normalized == NULL)
                {
                    LOG(LOG_ERR, "out of memory");
                    free(dir_normalized);
                    free(base);
                    return NULL;
                }

                // These are safe because the realloc() call above allocates
                // dir_normalized to be long enough.
                strcat(dir_normalized, "/");
                strcat(dir_normalized, base);

                free(base);

                return dir_normalized;
            }
        }
        else if (errno != ENOENT)
        {
            if (base == NULL)
            {
                config_message(context, LOG_ERR, "realpath(%s): %s", dir,
                               strerror(errno));
            }
            else
            {
                config_message(context, LOG_ERR,
                               "realpath(%s) for input \"%s\": %s",
                               dir, path, strerror(errno));
            }

            free(dir);
            free(base);

            return NULL;
        }

        copy_for_dirname = strdup(dir);
        if (copy_for_dirname == NULL)
        {
            LOG(LOG_ERR, "out of memory");
            free(dir);
            free(base);
            return NULL;
        }

        copy_for_basename = strdup(dir);
        if (copy_for_basename == NULL)
        {
            LOG(LOG_ERR, "out of memory");
            free(copy_for_dirname);
            free(dir);
            free(base);
            return NULL;
        }

        dir_dirname = dirname(copy_for_dirname);
        dir_basename = basename(copy_for_basename);

        if (strcmp(dir_dirname, dir) == 0)
        {
            config_message(context, LOG_ERR,
                           "infinite loop with dirname \"%s\" while parsing \"%s\"",
                           dir, path);
            free(copy_for_dirname);
            free(copy_for_basename);
            free(dir);
            free(base);
            return NULL;
        }

        // set dir to the parent of dir
        free(dir);
        dir = strdup(dir_dirname);
        free(copy_for_dirname);
        if (dir == NULL)
        {
            LOG(LOG_ERR, "out of memory");
            free(copy_for_basename);
            free(base);
            return NULL;
        }

        // set base to be relative to the new dir
        if (base == NULL)
        {
            base = strdup(dir_basename);
            free(copy_for_basename);
            if (base == NULL)
            {
                LOG(LOG_ERR, "out of memory");
                free(dir);
                return NULL;
            }
        }
        else
        {
            length = strlen(dir_basename) +
                     1 /* '/' */ +
                     strlen(base) +
                     1 /* null terminator */;
            tmp = base;
            base = malloc(length);
            if (base == NULL)
            {
                LOG(LOG_ERR, "out of memory");
                free(dir);
                free(tmp);
                free(copy_for_basename);
                return NULL;
            }
            snprintf(base, length, "%s/%s", dir_basename, tmp);
            free(tmp);
            free(copy_for_basename);
        }
    }
}

bool config_type_path_converter(
    const struct config_context * context,
    void *usr_arg,
    const char *input,
    void **data)
{
    (void)usr_arg;

    if (input == NULL)
    {
        config_message(context, LOG_ERR,
                       "paths can't be empty. "
                       "Use `.' to specify the current directory");
        return false;
    }

    *data = realpath_noent(context, input);
    if (*data == NULL)
    {
        return false;
    }

    return true;
}
