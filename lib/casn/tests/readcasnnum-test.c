#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include "casn/casn.h"

/*
 NOTE: This set of tests assumes that C signed integers are
 represented using two's complement encoding.  While this is not
 technically required by the ISO C Standard (ISO/IEC 9899:2011), most
 reasonable implementations these days do so.
*/

int main(void)
{
    struct casn number;
    unsigned char long_data[sizeof(long) + 1];
    unsigned char intmax_data[sizeof(intmax_t) + 1];
    int i, ret;
    long long_dest;
    intmax_t intmax_dest;

    /*
      FIXME: The following assumes the BBN ASN.1 library runs in
      32-bit mode only.  If 64-bit support is added, the following
      if-block should be generalized.
    */

    // Run tests only if:
    // 1) long appears to be 32-bit two's complement
    // 2) intmax_t appears to be 64-bit two's complement
    if (LONG_MAX != 0x7fffffffL ||
        LONG_MIN != (-0x7fffffffL - 1) ||
        INTMAX_MAX != 0x7fffffffffffffffLL ||
        INTMAX_MIN != (-0x7fffffffffffffffLL - 1))
    {
        /* Note: Use (-0x7fffffffL - 1) instead of -0x80000000L to
         * represent long 2^(-31).  The '-' has less precedence than
         * 'L', so 0x80000000L is promoted to long long. */
        fprintf(stderr, "Unexpected C signed integer representation. "
                "Skipping read_casn_num() test.\n");
        return 77; // automake return code for "skipped test"
    }

    simple_constructor(&number, 0, ASN_INTEGER);

    // Test read_casn_num() on long integer boundary conditions.
    // X.690 section 8.3 defines the ASN.1 integer encodings below (2's compl).
    // LONG_MIN - 1 should fail
    // LONG_MIN should succeed
    // LONG_MAX should succeed
    // LONG_MAX + 1 should fail

    // LONG_MIN - 1 should fail
    long_data[0] = 0xff;
    long_data[1] = 0x7f;
    for (i = 2; i < (int)sizeof(long_data); i++)
        long_data[i] = 0xff;
    write_casn(&number, long_data, sizeof(long_data));
    ret = read_casn_num(&number, &long_dest);
    if (ret != -1)
    {
        fprintf(stderr, "read_casn_num on LONG_MIN - 1 should fail.\n");
        return 1;
    }

    // LONG_MIN should succeed
    memset(long_data, 0, sizeof(long));
    long_data[0] = 0x80;
    write_casn(&number, long_data, sizeof(long));
    ret = read_casn_num(&number, &long_dest);
    if (ret != sizeof(long_dest) || long_dest != LONG_MIN)
    {
        fprintf(stderr, "read_casn_num on LONG_MIN failed.\n");
        return 1;
    }

    // LONG_MAX should succeed
    long_data[0] = 0x7f;
    for (i = 1; i < (int)sizeof(long); i++)
        long_data[i] = 0xff;
    write_casn(&number, long_data, sizeof(long));
    ret = read_casn_num(&number, &long_dest);
    if (ret != sizeof(long_dest) || long_dest != LONG_MAX)
    {
        fprintf(stderr, "read_casn_num on LONG_MAX failed.\n");
        return 1;
    }

    // LONG_MAX + 1 should fail
    memset(long_data, 0, sizeof(long_data));
    long_data[1] = 0x80;
    write_casn(&number, long_data, sizeof(long_data));
    ret = read_casn_num(&number, &long_dest);
    if (ret != -1)
    {
        fprintf(stderr, "read_casn_num on LONG_MAX + 1 should fail.\n");
        return 1;
    }

    // Test read_casn_num_max() on intmax_t boundary conditions.
    // INTMAX_MIN - 1 should fail
    // INTMAX_MIN should succeed
    // INTMAX_MAX should succeed
    // INTMAX_MAX + 1 should fail

    // INTMAX_MIN - 1 should fail
    intmax_data[0] = 0xff;
    intmax_data[1] = 0x7f;
    for (i = 2; i < (int)sizeof(intmax_data); i++)
        intmax_data[i] = 0xff;
    write_casn(&number, intmax_data, sizeof(intmax_data));
    ret = read_casn_num_max(&number, &intmax_dest);
    if (ret != -1)
    {
        fprintf(stderr, "read_casn_num_max on INTMAX_MIN - 1 should fail.\n");
        return 1;
    }

    // INTMAX_MIN should succeed
    memset(intmax_data, 0, sizeof(intmax_t));
    intmax_data[0] = 0x80;
    write_casn(&number, intmax_data, sizeof(intmax_t));
    ret = read_casn_num_max(&number, &intmax_dest);
    if (ret != sizeof(intmax_dest) || intmax_dest != INTMAX_MIN)
    {
        fprintf(stderr, "read_casn_num_max on INTMAX_MIN failed.\n");
        return 1;
    }

    // INTMAX_MAX should succeed
    intmax_data[0] = 0x7f;
    for (i = 1; i < (int)sizeof(intmax_t); i++)
        intmax_data[i] = 0xff;
    write_casn(&number, intmax_data, sizeof(intmax_t));
    ret = read_casn_num_max(&number, &intmax_dest);
    if (ret != sizeof(intmax_dest) || intmax_dest != INTMAX_MAX)
    {
        fprintf(stderr, "read_casn_num_max on INTMAX_MAX failed.\n");
        return 1;
    }

    // INTMAX_MAX + 1 should fail
    memset(intmax_data, 0, sizeof(intmax_data));
    intmax_data[1] = 0x80;
    write_casn(&number, intmax_data, sizeof(intmax_data));
    ret = read_casn_num_max(&number, &intmax_dest);
    if (ret != -1)
    {
        fprintf(stderr, "read_casn_num_max on INTMAX_MAX + 1 should fail.\n");
        return 1;
    }

    delete_casn(&number);
    return EXIT_SUCCESS;
}
