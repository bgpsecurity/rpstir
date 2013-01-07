#ifndef _UTIL_HASHUTILS_H
#define _UTIL_HASHUTILS_H

int gen_hash(
    unsigned char *inbufp,
    int bsize,
    unsigned char *outbufp,
    CRYPT_ALGO_TYPE alg);

#endif
