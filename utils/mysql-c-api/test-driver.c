#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "logutils.h"


/*==============================================================================
 * Use this for temporary test calls.
------------------------------------------------------------------------------*/
void useDbConn(MYSQL *mysqlp) {
//    uint32_t new_ser_num = 0xfffffffc;
//    addNewSerNum(mysqlp, &new_ser_num);

    addNewSerNum(mysqlp, NULL);

//    deleteSerNum(mysqlp, 1);

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

    if (connectMysqlCApi(&mysql, host, user, pass, db)) {
        log_msg(LOG_ERR, "could not get a connection to the db");
        return(-1);
    }

    useDbConn(&mysql);

    mysql_close(&mysql);

    return EXIT_SUCCESS;
}
