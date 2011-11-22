int getLatestSerNum(MYSQL *mysqlp, uint32_t *sn);
int addNewSerNum(MYSQL *mysqlp, const uint32_t *in);
int deleteSerNum(MYSQL *mysqlp, uint32_t ser_num);
int deleteAllSerNums(MYSQL *mysqlp);
int connectDb(void *dbp,
        const char *host,
        const char *user,
        const char *pass,
        const char *db);
int disconnectDb(void *dbp);
