#ifndef _DB_UTIL_H
#define _DB_UTIL_H


#include <inttypes.h>


int addCacheNonce(void *connp, uint16_t nonce);

int addNewSerNum(void *connp, const uint32_t *in);

int charp2uint16_t(uint16_t *out, const char *in, int len);

int charp2uint32_t(uint32_t *out, const char *in, int len);

int deleteAllSerNums(void *connp);

int deleteSerNum(void *connp, uint32_t ser_num);

int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]);


#endif // _DB_UTIL_H
