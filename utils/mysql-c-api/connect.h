int getCacheNonce(MYSQL *mysqlp, const uint16_t *nonce);

int addCacheNonce(MYSQL *mysqlp, const uint16_t *nonce);

int getLatestSerNum(void *connp, uint32_t *sn);

int addNewSerNum(void *connp, const uint32_t *in);

int deleteSerNum(void *connp, uint32_t ser_num);

int deleteAllSerNums(void *connp);

void *connectDb(
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

void disconnectDb(void *connp);
