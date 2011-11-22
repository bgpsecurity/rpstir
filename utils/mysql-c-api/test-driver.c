#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "logging.h"



/*==============================================================================
 * Use this for temporary test calls.
------------------------------------------------------------------------------*/
void useDbConn(MYSQL *mysqlp) {
//    uint32_t new_ser_num = 0xfffffffc;
//    addNewSerNum(mysqlp, &new_ser_num);

//    addNewSerNum(mysqlp, NULL);

    deleteSerNum(mysqlp, 99);

//    deleteAllSerNums(mysqlp);

//    getLatestSerNum(mysqlp);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int main(/*int argc, char **argv*/) {
    MYSQL mysql;
    const char host[] = "localhost";
    const char user[] = "rpki";
    const char pass[] = "validator";
    const char db[] = "rpkidb7";

    DB_C_OPEN_LOG();

    if (connectMysqlCApi(&mysql, host, user, pass, db)) {
        DB_C_LOG(LOG_ERR, "could not get a connection to the db");
        return(-1);
    }

    useDbConn(&mysql);

    mysql_close(&mysql);

    DB_C_CLOSE_LOG();

    return EXIT_SUCCESS;
}
