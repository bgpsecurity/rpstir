#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "util.h"
#include "logging.h"


/*==============================================================================
------------------------------------------------------------------------------*/
int ch2int(int *out, char in) {
    switch (in) {
    case '0':
        *out = 0;
        break;
    case '1':
        *out = 1;
        break;
    case '2':
        *out = 2;
        break;
    case '3':
        *out = 3;
        break;
    case '4':
        *out = 4;
        break;
    case '5':
        *out = 5;
        break;
    case '6':
        *out = 6;
        break;
    case '7':
        *out = 7;
        break;
    case '8':
        *out = 8;
        break;
    case '9':
        *out = 9;
        break;
    default:
        if (isprint(in))
            LOG(LOG_ERR, "expected digit, got '%c'", in);
        else
            LOG(LOG_ERR, "expected digit, got '0x%02x'", (unsigned char)in);
        return (-1);
        break;
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int charp2uint32_t(uint32_t *out, const char *in, int len) {
    const int MAX_LEN = 10;  // decimal digits for type
    char terminated_input[MAX_LEN + 1];
    uint64_t tmp_out = 0;

    if (len > MAX_LEN) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        if (isdigit(in[i])) {
            terminated_input[i] = in[i];
        } else {
            LOG(LOG_ERR, "input char was not a digit");
            return (-1);
        }
    }
    terminated_input[i] = '\0';

    int ret = 0;
    ret = sscanf(terminated_input, "%" SCNu64, &tmp_out);
    if (ret == 0) {
        LOG(LOG_ERR, "no sscanf conversion done");
        return (-1);
    } else if (ret < 0) {
        LOG(LOG_ERR, "sscanf error %d", ret);
        return (-1);
    }

    if (tmp_out > UINT32_MAX) {
        LOG(LOG_ERR, "input exceeds max value");
        return (-1);
    } else
        *out = (uint32_t) tmp_out;

    return (0);
}


/*==============================================================================
 * TODO: possibly generalize to more numeric types.
------------------------------------------------------------------------------*/
int charp2uint16_t(uint16_t *out, const char *in, int len) {
    const int MAX_LEN = 5;  // decimal digits for type
    char terminated_input[MAX_LEN + 1];
    uint32_t tmp_out = 0;

    if (len > MAX_LEN) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        if (isdigit(in[i])) {
            terminated_input[i] = in[i];
        } else {
            LOG(LOG_ERR, "input char was not a digit");
            return (-1);
        }
    }
    terminated_input[i] = '\0';

    int ret = 0;
    ret = sscanf(terminated_input, "%" SCNu32, &tmp_out);
    if (ret == 0) {
        LOG(LOG_ERR, "no sscanf conversion done");
        return (-1);
    } else if (ret < 0) {
        LOG(LOG_ERR, "sscanf error %d", ret);
        return (-1);
    }

    if (tmp_out > UINT16_MAX) {
        LOG(LOG_ERR, "input exceeds max value");
        return (-1);
    } else
        *out = (uint16_t) tmp_out;

    return (0);
}


/*==============================================================================
 * Note:  not using this.  use charp2uint32_t(), instead.
------------------------------------------------------------------------------*/
int char_arr2uint32_t(uint32_t *out, const char *in, int len) {
    int i;
    int digit = 0;
    uint64_t val = 0;

    if (len > 10) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    for (i = 0; i < len; i++) {
        val *= 10;
        if (ch2int(&digit, in[i])) {
            return (-1);
        }
        val += digit;
    }

    if (val > 0xffffffff) {
        LOG(LOG_ERR, "value exceeds max size");
        return (-1);
    }

    *out = (uint32_t) val;

    return (0);
}
