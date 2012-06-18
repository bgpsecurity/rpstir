/*
 * Low-level string parsing utilities 
 */


#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "stringutils.h"


/*
 * Does string s end with suffix? 
 */
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


/*
 * Does string s start with prefix? 
 */
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


/*
 * Return true if the string contains at least one non-delimiter character.  
 */
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


/*
 * Strip all leftmost delimiter characters from input string (in place). 
 */
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


/*
 * Strip all rightmost delimiter characters from input string (in place). 
 */
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


/*
 * Strip all leftmost and rightmost delimiter characters (in place). 
 */
void strip(
    char *s,
    const char *delimiters)
{
    lstrip(s, delimiters);
    rstrip(s, delimiters);
}


/*
 * Return the next field, i.e. pointer to the beginning of the next contiguous 
 * string of non-delimiter characters.  Note that this skips the current
 * contiguous string of non-delimiter characters. Returns NULL if there are no 
 * more non-delimiter characters in the string. 
 */
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


/*
 * Copy the directory string for a particular path to the destination buffer.
 * A path which ends in '/' will simply be copied, whereas a path with no '/'
 * returns the string ".".  At most dest_len characters will be copied,
 * including the terminating '\0'.  If dest_len was not enough space, a NULL
 * is returned. 
 */
char *dirname(
    char *dest,
    int dest_len,
    const char *path)
{
    const char *right_most_slash;
    int dir_length;

    if (!path)
        return NULL;

    /*
     * Search for right-most slash. 
     */
    right_most_slash = strrchr(path, '/');
    if (!right_most_slash)
    {
        if (dest_len < 2)
            return NULL;
        else
            return strcpy(dest, ".");
    }

    /*
     * Copy directory substring, terminating with null. 
     */
    dir_length = right_most_slash - path + 1;
    if (dir_length > dest_len - 1)
        return NULL;
    strncpy(dest, path, dir_length);
    dest[dir_length] = '\0';

    return dest;
}

/*
 * Copy the current field (contiguous string of non-delimiter characters) into 
 * the destination buffer, up to dest_length-1 bytes. Append '\0' to terminate 
 * the C string.  If the buffer size is insufficient, safely null-terminate
 * the destination buffer and return NULL. 
 */
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


/*
 * Return the length of the current field (contiguous string of non-delimiter
 * characters).  Returns -1 on error cases. 
 */
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


/*
 * Split a string on given delimiters.
 * 
 * This modifies the original string by terminating each field with a NULL
 * character.  The function also allocates an array of char* and populates it
 * with pointers back into the original string, each pointer indicating the
 * start of a field.  The caller is responsible for freeing the memory
 * allocated at address *pfields.
 * 
 * Intuitively, if the delimiters are whitespace, this function parses a
 * command line string into char *argv[] and sets argc.  Strictly speaking,
 * this is not a complete replica of command line parsing because quoting is
 * not supported.
 * 
 * Inputs: s - string to be split delimiters - list of characters to split on
 * (field delimiters)
 * 
 * Outputs: s - string is modified in place pfields - address of char** that
 * will store the array of fields pnumfields - address of int that will store
 * the number of fields
 * 
 * Returns: 0 on success, -1 on failure and sets errno accordingly. 
 */
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


/*
 * Expand an array by doubling the amount of elements allocated. Behaves much
 * like realloc(), and so the following two paragraphs are copied from the
 * realloc() man page for reference: realloc() changes the size of the memory 
 * block pointed to by ptr to size bytes.  The contents will be unchanged to
 * the minimum of the old and new sizes; newly allocated memory will be
 * uninitialized.  If ptr is NULL, the call is equivalent to malloc(size); if
 * size is equal to zero, the call is equivalent to free(ptr).  Unless ptr is
 * NULL, it must have been returned by an earlier call to malloc(), calloc()
 * or realloc().  Returns a pointer to the newly allocated memory, which is
 * suitably aligned for any kind of variable and may be different from ptr, or 
 * NULL if the request fails. If size was equal to 0, either NULL or a pointer 
 * suitable to be passed to free() is returned.  If realloc() fails the
 * original block is left untouched - it is not freed or moved. Inputs: ptr
 * - address of pointer to array of members (*ptr may be NULL). current_nmemb
 * - current number of members allocated for the array min_nmemb - minimum
 * number of members requested for the output array Outputs: If the
 * realloc_by_doubling() was successful, *ptr is updated to the new pointer,
 * and *current_nmemb is updated to the new number of members.  Note that you
 * won't get the expected exponential reallocation if you call this more than
 * about 30 times, since size_t is often 32 bits. Returns: 0 on success; -1
 * and sets errno on failure. 
 */

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

/**=============================================================================
 * @brief Replace questionable chars from string for printing.
 *
 * @note Caller handles memory for dst.
 * @note Output might be truncated, compared to input.
 * @note dst will be null terminated, at or before index dst_sz-1.
------------------------------------------------------------------------------*/
char *scrub_for_print(
    char *dst,
    char const *src,
    size_t const dst_sz,
    size_t * dst_len_out,
    char const *other_chars_to_escape)
{
    size_t i;
    size_t used;

    dst[0] = '\0';

    for (i = 0, used = 0; i < dst_sz - 1; i++)
    {
        if ('\0' == src[i])
        {
            break;
        }
        else if (!isprint((int)(unsigned char)src[i])
                 || (isspace((int)(unsigned char)src[i]) && ' ' != src[i]))
        {
            used +=
                snprintf(&dst[used], dst_sz - used, "\\x%02" PRIx8, src[i]);
        }
        else if (strchr(other_chars_to_escape, src[i]))
        {
            used += snprintf(&dst[used], dst_sz - used, "\\%c", src[i]);
        }
        else if ('\\' == src[i])
        {
            used += snprintf(&dst[used], dst_sz - used, "\\%c", src[i]);
        }
        else
        {
            used += snprintf(&dst[used], dst_sz - used, "%c", src[i]);
        }
    }

    if (dst_len_out)
        *dst_len_out = used;

    return dst;
}
