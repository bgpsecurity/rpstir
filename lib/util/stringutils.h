#ifndef LIB_UTIL_STRINGUTILS_H
#define LIB_UTIL_STRINGUTILS_H

/*
 * Low-level string parsing utilities
 */

#include <stddef.h>

/*
 * Does string s end with suffix?
 */
int endswith(
    const char *s,
    const char *suffix);

/*
 * Does string s start with prefix?
 */
int startswith(
    const char *s,
    const char *prefix);

/*
 * Strip all leftmost delimiter characters from input string (in place).
 */
void lstrip(
    char *s,
    const char *delimiters);

/*
 * Strip all rightmost delimiter characters from input string (in place).
 */
void rstrip(
    char *s,
    const char *delimiters);

/*
 * Strip all leftmost and rightmost delimiter characters (in place).
 */
void strip(
    char *s,
    const char *delimiters);

/*
 * Return true if the string contains at least one non-delimiter character.
 */
int exists_non_delimiter(
    const char *s,
    const char *delimiters);

/*
 * Return the next field, i.e. pointer to the beginning of the next contiguous
 * string of non-delimiter characters.  Note that this skips the current
 * contiguous string of non-delimiter characters. Returns NULL if there are no
 * more non-delimiter characters in the string.
 */
char *start_of_next_field(
    const char *s,
    const char *delimiters);

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
    const char *delimiters);

/*
 * Return the length of the current field (contiguous string of non-delimiter
 * characters).  Returns -1 on error cases.
 */
int field_length(
    const char *s,
    const char *delimiters);

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
    int *pnumfields);

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
    size_t min_nmemb);

/**=============================================================================
 * @brief Replace questionable chars from string for printing.
 *
 * @note Caller handles memory for dst.
 * @note dst will be null terminated, at or before index dst_sz-1.
 *
 * @param[out] dst
 *     Location of the buffer to hold the output string.  This must
 *     not be NULL.
 * @param[in] src
 *     The input string to escape.  This must not be NULL.
 * @param[in] dst_sz
 *     Size of the buffer at @p dst.  The buffer must be big enough to
 *     hold the entire escaped string, including the nul terminator.
 * @param[out] dst_len_out
 *     On return, the value at this location will be set to the length
 *     of the escaped string (excluding the nul terminator).  This
 *     parameter may be NULL.
 * @param[in] other_chars_to_escape
 *     nul-terminated array of additional characters to escape with a
 *     backslash.  This must not be NULL.
 *
 * @return dst
------------------------------------------------------------------------------*/
char *scrub_for_print(
    char *dst,
    char const *src,
    size_t const dst_sz,
    size_t * dst_len_out,
    char const *other_chars_to_escape);

#endif /* !LIB_UTIL_STRINGUTILS_H */
