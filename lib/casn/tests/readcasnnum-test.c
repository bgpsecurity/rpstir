#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include "casn/casn.h"
#include "test/unittest.h"

/*
 NOTE: This set of tests assumes that C signed integers are
 represented using two's complement encoding.  While this is not
 technically required by the ISO C Standard (ISO/IEC 9899:2011), most
 reasonable implementations these days do so.
*/


/**
    Test if a signed integer type appears to be twos complement.

    @param data_size sizeof(the integer type)
    @param data_min the minimum value for the type
    @param data_max the maximum value for the type
*/
static bool maybe_twos_complement(
    size_t data_size,
    intmax_t data_min,
    intmax_t data_max)
{
    intmax_t twos_min;
    intmax_t twos_max;
    size_t i;

    twos_max = 0x7f;
    for (i = 1; i < data_size; ++i)
    {
        twos_max = (twos_max << 8) | 0xff;
    }
    twos_min = -twos_max - 1;

    return data_min == twos_min && data_max == twos_max;
}

static bool test_twos_complement()
{
    TEST_BOOL(maybe_twos_complement(sizeof(long), LONG_MIN, LONG_MAX),
        true);

    TEST_BOOL(maybe_twos_complement(sizeof(intmax_t), INTMAX_MIN, INTMAX_MAX),
        true);

    return true;
}

/**
    Fill data with (minimum twos-complement int of length len) - 1

    @param data buffer of length at least len+1
    @return actual number of bytes written
*/
static size_t fill_min_minus(
    uint8_t * data,
    size_t len)
{
    memset(data, 0xff, len + 1);
    data[1] = 0x7f;
    return len + 1;
}

/**
    Fill data with (minimum twos-complement int of length len)
    encoded as specified by X.690 section 8.3.

    @param data buffer of length at least len
    @return actual number of bytes written
*/
static size_t fill_min(
    uint8_t * data,
    size_t len)
{
    memset(data, 0, len);
    data[0] = 0x80;
    return len;
}

/**
    Fill data with (maximum twos-complement int of length len)
    encoded as specified by X.690 section 8.3.

    @param data buffer of length at least len
    @return actual number of bytes written
*/
static size_t fill_max(
    uint8_t * data,
    size_t len)
{
    memset(data, 0xff, len);
    data[0] = 0x7f;
    return len;
}

/**
    Fill data with (maximum twos-complement int of length len) + 1
    encoded as specified by X.690 section 8.3.

    @param data buffer of length at least len+1
    @return actual number of bytes written
*/
static size_t fill_max_plus(
    uint8_t * data,
    size_t len)
{
    memset(data, 0, len + 1);
    data[1] = 0x80;
    return len + 1;
}

int main(void)
{
    struct casn number;
    uint8_t data[sizeof(intmax_t) + 1];
    size_t data_len;
    int ret;
    long long_dest;
    intmax_t intmax_dest;

    if (!test_twos_complement())
    {
        fprintf(stderr, "Unexpected C signed integer representation. "
                "Skipping read_casn_num() test.\n");
        return 77; // automake return code for "skipped test"
    }

    simple_constructor(&number, 0, ASN_INTEGER);

    /**
        Test read_casn_num or read_casn_num_max on their respective boundary
        conditions.

        @param read_func read_casn_num or read_casn_num_max
        @param dest variable with an integer type appropriate for read_func
        @param min minimum value possible for the type
        @param max maximum value possible for the type

        min - 1 should fail
        min should succeed
        max should succeed
        max + 1 should fail
    */
    #define TEST_READ_CASN_NUM(read_func, dest, min, max) \
        do { \
            data_len = fill_min_minus(data, sizeof(dest)); \
            write_casn(&number, data, data_len); \
            ret = read_func(&number, &dest); \
            if (ret != -1) \
            { \
                fprintf(stderr, "%s on %s - 1 should fail.\n", \
                    #read_func, #min); \
                return 1; \
            } \
            \
            data_len = fill_min(data, sizeof(dest)); \
            write_casn(&number, data, data_len); \
            ret = read_func(&number, &dest); \
            if (ret != sizeof(dest) || dest != min) \
            { \
                fprintf(stderr, "%s on %s failed.\n", #read_func, #min); \
                return 1; \
            } \
            \
            data_len = fill_max(data, sizeof(dest)); \
            write_casn(&number, data, data_len); \
            ret = read_func(&number, &dest); \
            if (ret != sizeof(dest) || dest != max) \
            { \
                fprintf(stderr, "%s on %s failed.\n", #read_func, #max); \
                return 1; \
            } \
            \
            data_len = fill_max_plus(data, sizeof(dest)); \
            write_casn(&number, data, data_len); \
            ret = read_func(&number, &dest); \
            if (ret != -1) \
            { \
                fprintf(stderr, "%s on %s + 1 should fail.\n", \
                    #read_func, #max); \
                return 1; \
            } \
        } while (false)

    TEST_READ_CASN_NUM(read_casn_num, long_dest, LONG_MIN, LONG_MAX);
    TEST_READ_CASN_NUM(read_casn_num_max, intmax_dest, INTMAX_MIN, INTMAX_MAX);

    #undef TEST_READ_CASN_NUM

    delete_casn(&number);
    return EXIT_SUCCESS;
}
