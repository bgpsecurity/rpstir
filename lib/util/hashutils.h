#ifndef _UTIL_HASHUTILS_H
#define _UTIL_HASHUTILS_H

#include <cryptlib.h>

int gen_hash(
    unsigned char *inbufp,
    int bsize,
    unsigned char *outbufp,
    CRYPT_ALGO_TYPE alg);

#endif
