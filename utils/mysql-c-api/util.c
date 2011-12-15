#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "logging.h"
#include "util.h"


/*==============================================================================
 * @note Caller must free memory returned in first argument.
 * @ret 0 on success, -1 on failure, 1 on NULL value.
------------------------------------------------------------------------------*/
int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]) {
    uint num_fields;
    int field_no = -1;
    uint i = 0;
    MYSQL_FIELD *fields = NULL;
    ulong *lengths = NULL;
    ulong len;

    if (row == NULL) {
        LOG(LOG_ERR, "the argument row is NULL");
        return -1;
    }

    num_fields = mysql_num_fields(result);
    fields = mysql_fetch_fields(result);
    for (i = 0; i < num_fields; i++) {
        if (!strcmp(fields[i].name, field_name)) {
            field_no = i;
            break;
        }
    }
    if (field_no == -1) {
        LOG(LOG_ERR, "could not find field name:  %s", field_name);
        return -1;
    }

    lengths = mysql_fetch_lengths(result);  // mysql allocs the memory
    len = lengths[field_no];

    *out = (char*) malloc(len + 1);
    if (!(*out)) {
        LOG(LOG_ERR, "could not alloc memory");
        return -1;
    }

    (*out)[len] = '\0';
    for (i = 0; i < len; i++) {
        (*out)[i] = row[field_no][i];
    }

    return 0;
}
