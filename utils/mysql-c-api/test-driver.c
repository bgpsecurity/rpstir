#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "prep-stmt.h"
#include "rtr.h"
#include "test-driver.h"
#include "util.h"


/*==============================================================================
 * Use this for temporary test calls.
------------------------------------------------------------------------------*/
void db_use_conn(dbconn *conn) {
    (void) conn;  // to avoid -Wunused-parameter

    uint16_t session;
    db_rtr_get_session_id(conn, &session);
    printf("session = %" PRIu16 "\n", session);

//    setCacheNonce(conn, 3434);

//    int ret;
//    uint32_t sn = 0;
//    ret = getLatestSerialNumber(conn, &sn, 0);
//    if (ret == 0) {
//        printf("serial number found:  %" PRIu32 "\n", sn);
//    } else if (ret == 1) {
//        puts("no serial numbers in the db\n");
//    } else if (ret == -1) {
//        puts("some error occurred\n");
//    }

//    uint32_t ser_num = 0xfffffffc;
//    addNewSerNum(conn, &ser_num);
//    printf("serial number = %u\n", ser_num);

//    addNewSerNum(conn, NULL);

//    deleteSerNum(conn, 99);

//    deleteAllSerNums(conn);

//    void **ptr = NULL;
//    startSerialQuery(conn, ptr, 5);

//    char field_str[] = "192.ec.44.55/18(22)";  // not accepted
//    char field_str[] = "192.168.44.55/18(22)";
//    char field_str[] = "192.168.44.55/18";
//    char field_str[] = "1:2:3:4:5:6:7:8/18(22)";
//    char field_str[] = "fe80:2:3:4:5:6:7:8/18(22)";
//    char field_str[] = "1:2:0:0:5:6:7:8/18(22)";
//    char field_str[] = "1:2::5:6:7:8/18(22)";
//    char field_str[] = "1:0002:3:4:5:6:7:8/18(22)";
//    uint family = 0;
//    struct in_addr addr4;
//    struct in6_addr addr6;
//    uint prefix_len = 0;
//    uint max_prefix_len = 0;
//    printf("sending <%s>\n", field_str);
//    if (parseIpaddr(&family, &addr4, &addr6, &prefix_len, &max_prefix_len,
//            field_str)) {
//        puts("could not parse ip_addr");
//        return;
//    }
//
//    printf("family is %d\n", family);
//    printf("prefix_len is %u\n", prefix_len);
//    printf("max_prefix_len is %u\n", max_prefix_len);
//    printf("\n");
}


/*==============================================================================
------------------------------------------------------------------------------*/
int main() {
    int client_types = 0;
    dbconn *conn = NULL;
//    const char host[] = "localhost";
//    const char user[] = "rpki";
//    const char pass[] = "validator";
//    const char db[] = "rpkidb7";

    OPEN_LOG();

//    if ((conn = db_connect(host, user, pass, db)) == NULL) {
    client_types |= DB_CLIENT_RTR;
    if ((conn = db_connect_default(client_types)) == NULL) {
        CLOSE_LOG();
        return -1;
    }

    db_use_conn(conn);

    db_disconnect(conn);

    CLOSE_LOG();

    return EXIT_SUCCESS;
}
