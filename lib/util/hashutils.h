#include <util/cryptlib_compat.h>

extern int CryptInitState;

int gen_hash(
    unsigned char *inbufp,
    int bsize,
    unsigned char *outbufp,
    CRYPT_ALGO_TYPE alg);
