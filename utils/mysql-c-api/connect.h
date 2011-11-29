#ifndef _DB_CONNECT_H
#define _DB_CONNECT_H


#include <inttypes.h>


void *connectDb(
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

void *connectDbDefault();

void disconnectDb(void *connp);


#endif // _DB_CONNECT_H
