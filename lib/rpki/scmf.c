#include "scmf.h"
#include "util/stringutils.h"
#include <assert.h>

int
where_append(
    char *restrict buf,
    const char *restrict format,
    ...)
{
    va_list ap;
    va_start(ap, format);
    int ret = where_append_v(buf, format, ap);
    va_end(ap);
    return ret;
}

int
where_append_v(
    char *restrict buf,
    const char *restrict format,
    va_list ap)
{
    size_t len = strlen(buf);
    assert(len <= WHERESTR_SIZE);
    return xvsnprintf(&buf[len], WHERESTR_SIZE - len, format, ap);
}
