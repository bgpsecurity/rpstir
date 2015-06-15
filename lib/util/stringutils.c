/*
 * Low-level string parsing utilities
 */

#include "stringutils.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


int endswith(
    const char *s,
    const char *suffix)
{
    int s_len,
        suffix_len;

    if (!s || !suffix)
        return 0;

    s_len = strlen(s);
    suffix_len = strlen(suffix);
    if (s_len < suffix_len)
        return 0;

    if (strncmp(&s[s_len - suffix_len], suffix, suffix_len) == 0)
        return 1;
    else
        return 0;
}


int startswith(
    const char *s,
    const char *prefix)
{
    int s_len,
        prefix_len;

    if (!s || !prefix)
        return 0;

    s_len = strlen(s);
    prefix_len = strlen(prefix);
    if (s_len < prefix_len)
        return 0;

    if (strncmp(s, prefix, prefix_len) == 0)
        return 1;
    else
        return 0;
    return 0;
}


int exists_non_delimiter(
    const char *s,
    const char *delimiters)
{
    const char *pc;
    if (!s || !delimiters)
        return 0;

    for (pc = s; *pc != '\0'; ++pc)
        if (!strchr(delimiters, *pc))
            return 1;

    return 0;
}


void lstrip(
    char *s,
    const char *delimiters)
{
    int i,
        len,
        num_leftmost_delims;
    if (!s || !delimiters)
        return;
    len = strlen(s);
    num_leftmost_delims = 0;
    for (i = 0; i < len && strchr(delimiters, s[i]); i++)
        num_leftmost_delims++;
    if (num_leftmost_delims > 0)
        memmove(s, &s[num_leftmost_delims], len - num_leftmost_delims + 1);
}


void rstrip(
    char *s,
    const char *delimiters)
{
    int i,
        len;
    if (!s || !delimiters)
        return;
    len = strlen(s);
    for (i = len - 1; i >= 0 && strchr(delimiters, s[i]); i--)
        s[i] = '\0';
}


void strip(
    char *s,
    const char *delimiters)
{
    lstrip(s, delimiters);
    rstrip(s, delimiters);
}


char *start_of_next_field(
    const char *s,
    const char *delimiters)
{
    const char *pc;

    if (!s || !delimiters)
        return NULL;

    /*
     * Skip current set of non-delimiters
     */
    for (pc = s; *pc != '\0' && !strchr(delimiters, *pc); ++pc);

    /*
     * Skip delimiters
     */
    for (; *pc != '\0' && strchr(delimiters, *pc); ++pc);

    if (*pc == '\0')            /* end of string */
        return NULL;

    return (char *)pc;
}


char *this_field(
    char *dest,
    int dest_length,
    const char *src,
    const char *delimiters)
{
    const char *pc = src;
    int bytes_written = 0;
    int insufficient_buffer = 0;

    if (!dest || dest_length < 1 || !src || !delimiters)
        return NULL;

    while (*pc != '\0' && !strchr(delimiters, *pc))
    {
        if (bytes_written == dest_length - 1)
        {
            insufficient_buffer = 1;
            break;
        }
        dest[bytes_written] = *pc;
        bytes_written++;
        pc++;
    }
    dest[bytes_written] = '\0';

    if (insufficient_buffer)
        return NULL;
    else
        return dest;
}


int field_length(
    const char *s,
    const char *delimiters)
{
    int len = 0;
    if (!s || !delimiters)
        return -1;
    while (*s != '\0' && !strchr(delimiters, *s))
    {
        len++;
        s++;
    }
    return len;
}


int split_string(
    char *s,
    const char *delimiters,
    char ***pfields,
    int *pnumfields)
{
    char **fields = NULL;       /* array of char*, like argv */
    char *strtok_state;         /* for strtok_r's use only */
    size_t num_fields = 0;      /* number of fields actually recorded */
    size_t fields_capacity = 0; /* capacity of fields array */
    char *current_field = NULL;

    if (!delimiters || !s || !pfields || !pnumfields)
    {
        errno = EINVAL;
        return -1;
    }

    /*
     * Find first field.
     */
    current_field = strtok_r(s, delimiters, &strtok_state);
    if (current_field)
    {                           /* allocate field array as necessary */
        if (expand_by_doubling((void *)&fields, sizeof(char *),
                               &fields_capacity, num_fields + 1) != 0)
        {
            if (fields)
                free(fields);
            return -1;
        }
        fields[num_fields] = current_field;
        num_fields++;
    }

    /*
     * Find subsequent fields.
     */
    while (current_field)
    {
        current_field = strtok_r(NULL, delimiters, &strtok_state);
        if (current_field)
        {                       /* expand field array as necessary */
            if (expand_by_doubling((void *)&fields, sizeof(char *),
                                   &fields_capacity, num_fields + 1) != 0)
            {
                if (fields)
                    free(fields);
                return -1;
            }
            fields[num_fields] = current_field;
            num_fields++;
        }
    }

    *pfields = fields;
    *pnumfields = num_fields;

    return 0;
}


int expand_by_doubling(
    void **ptr,
    size_t size,
    size_t * current_nmemb,
    size_t min_nmemb)
{
    void *new_ptr = NULL;
    size_t new_nmemb = 1;

    if (!ptr || !current_nmemb)
    {
        errno = EINVAL;
        return -1;
    }

    if (*current_nmemb >= min_nmemb)
        return 0;

    /*
     * Double current_nmemb, yet be graceful about integer overflow. Note that
     * signed integer overflow is undefined, so it's important that we're
     * using size_t which is guaranteed to be unsigned.
     */
    new_nmemb = (new_nmemb * size > min_nmemb * size) ? new_nmemb : min_nmemb;
    new_nmemb = (new_nmemb * size > 2 * (*current_nmemb) * size) ?
        new_nmemb : 2 * (*current_nmemb);

    if (*current_nmemb >= new_nmemb)
    {
        errno = ENOMEM;
        return -1;
    }

    new_ptr = realloc(*ptr, new_nmemb * size);
    if (!new_ptr)
    {
        errno = ENOMEM;
        return -1;
    }

    *ptr = new_ptr;
    *current_nmemb = new_nmemb;
    return 0;
}

char *scrub_for_print(
    char *dst,
    char const *src,
    size_t const dst_sz,
    size_t * dst_len_out,
    char const *other_chars_to_escape)
{
    size_t i;
    size_t len_out = 0;
    // 'used' equals 'len_out' until the output becomes truncated, at
    // which point it is set to 'dst_sz'
    size_t used = 0;

    if (dst_sz)
    {
        dst[0] = '\0';
    }

    for (i = 0; src[i]; i++)
    {
        char const *fmt = "%c";

        if (!isprint((int)(unsigned char)src[i])
            || (isspace((int)(unsigned char)src[i]) && ' ' != src[i]))
        {
            fmt = "\\x%02" PRIx8;
        }
        else if (other_chars_to_escape && strchr(other_chars_to_escape, src[i]))
        {
            fmt = "\\%c";
        }
        else if ('\\' == src[i])
        {
            fmt = "\\%c";
        }

        int ret = snprintf(&dst[used], dst_sz - used, fmt, src[i]);
        if (ret < 0)
        {
            return NULL;
        }
        len_out += ret;
        used += ((size_t)ret > (dst_sz - used)) ? (dst_sz - used) : (size_t)ret;
    }

    if (dst_len_out)
    {
        *dst_len_out = len_out;
    }

    return dst;
}
