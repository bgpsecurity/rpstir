#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "test-driver.h"



/*==============================================================================
 * Use this for temporary test calls.
------------------------------------------------------------------------------*/
void useDbConn(void *connp) {
//    uint32_t new_ser_num = 0xfffffffc;
//    addNewSerNum(connp, &new_ser_num);

//    addNewSerNum(connp, NULL);

    deleteSerNum(connp, 99);

//    deleteAllSerNums(connp);

//    getLatestSerNum(connp);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int main() {
    void *connp = 0;
    const char host[] = "localhost";
    const char user[] = "rpki";
    const char pass[] = "validator";
    const char db[] = "rpkidb7";

    OPEN_LOG();

    if (connectDb(connp, host, user, pass, db)) {
        return(-1);
    }

    useDbConn(connp);

    disconnectDb(connp);

    CLOSE_LOG();

    return EXIT_SUCCESS;
}
