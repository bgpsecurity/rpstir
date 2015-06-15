#ifndef _LIB_UTIL_FILE_H
#define _LIB_UTIL_FILE_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>


/**
 * Create a directory and all its parents as needed.
 *
 * See mkdir(2) for description of mode.
 *
 * @note This function is not thread-safe.
 *
 * @return true on success, false on error. If false is returned, errno
 *         will be set to an appropriate value.
 */
bool mkdir_recursive(
    const char *pathname,
    mode_t mode);

#endif
