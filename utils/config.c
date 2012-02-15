#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "logging.h"


static int have_loaded_file = 0;
static size_t const MAX_KEY_LEN = 63;
static size_t const MAX_VALUE_LEN = 63;
static size_t const MAX_LINE_LEN = 1020;

struct item {
    char *key;
    char *val;
    struct item *next;
};

static struct item *first = NULL;
static struct item *last = NULL;


/** ============================================================================
------------------------------------------------------------------------------*/
void config_refresh(void) {
    have_loaded_file = 0;
}

/** ============================================================================
 * Lines starting with '#' are ignored.
 * Lines without an '=' are ignored.
 * The first greedy match of ([A-Z_a-z][0-9A-Z_a-z]*) on a line is the key.
 *   All other characters before the first '=' on the line are ignored.
 * Keys are case sensitive.
 * Keys are limited to 63 characters in length.
 * The value is everything between the first '=' and the '\n'.
------------------------------------------------------------------------------*/
static int parse_line(char const *line) {
    size_t line_len = strlen(line);
    char ch;
    size_t i;
    size_t key_first;
    size_t key_last;
    size_t val_first;
    size_t val_last;
    size_t equal_index;
    struct item *itm;
    size_t key_len;
    size_t val_len;
    char *key;
    char *val;

    // check for comment
    if ('#' == line[0])
        return 0;

    // find beginning of key
    i = 0;
    while (i < line_len) {
        ch = line[i];
        if ((ch >= 'a' && ch <= 'z') ||
                ch == '_' ||
                (ch >= 'A' && ch <= 'Z')) {
            key_last = key_first = i;
            i++;
            break;
        }
        i++;
    }

    // find end of key
    while (i < line_len) {
        ch = line[i];
        if (!((ch >= 'a' && ch <= 'z') ||
                ch == '_' ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9'))) {
            key_last = i - 1;
            break;
        }
        i++;
    }

    // find '='
    equal_index = 0;
    while (i < line_len) {
        ch = line[i];
        if (ch == '=') {
            equal_index = i;
            break;
        }
        i++;
    }

    if (!equal_index)
        return 0;

    // extract key, value
    itm = malloc(sizeof(struct item));
    key_len = key_last - key_first + 1;
    key = strndup(&line[key_first], key_len);
    val_first = equal_index + 1;
    val_last = line_len - 2;  // removes '\n'
    val_len = val_last - val_first + 1;
    val = strndup(&line[equal_index + 1], val_len);
    if (!itm  ||  !key  ||  !val) {
        LOG(LOG_ERR, "out of memory");
        return -1;
    }
    itm->key = key;
    itm->val = val;
    itm->next = NULL;

    if (!first) {
        first = itm;
        last = itm;
    } else {
        last->next = itm;
        last = itm;
    }

    return 0;
}

/** ============================================================================
------------------------------------------------------------------------------*/
int config_load_test_file(char *config_file) {
    FILE *fp;
    char line[MAX_LINE_LEN + 3];
    size_t line_len;

    fp = fopen(config_file, "r");
    if (!fp) {
        LOG(LOG_ERR, "Could not open file '%s'", config_file);
        return -1;
    }

    have_loaded_file = 1;
    first = NULL;
    last = NULL;

    while (fgets(line, sizeof(line), fp)) {
        line_len = strlen(line);

        // skip lines that are too long
        if (MAX_LINE_LEN < line_len) {
            do {  // consume rest of too-long-line
                if ('\n' == line[line_len - 1])
                    continue;
            } while (fgets(line, sizeof(line), fp));
            break;  // no more lines
        }

        if (parse_line(line))
            return -1;
    }

    fclose(fp);
    return 0;
}

/** ============================================================================
------------------------------------------------------------------------------*/
static int config_load_file(void) {
    int const MAX = 1023;
    char config_file[MAX + 1];
    FILE *fp;
    char line[MAX_LINE_LEN + 3];
    size_t line_len;

    strncpy(config_file, getenv("RPKI_ROOT"), MAX);
    config_file[MAX + 1] = '\0';
    strncat(config_file, "/", sizeof(config_file) - strlen(config_file) - 1);
    strncat(config_file, RPSTIR_CONFIG_FILE,
            sizeof(config_file) - strlen(config_file) - 1);
    fp = fopen(config_file, "r");
    if (!fp) {
        LOG(LOG_ERR, "Could not open file '%s'", config_file);
        return -1;
    }

    have_loaded_file = 1;
    first = NULL;
    last = NULL;

    while (fgets(line, sizeof(line), fp)) {
        line_len = strlen(line);

        // skip lines that are too long
        if (MAX_LINE_LEN < line_len) {
            do {  // consume rest of too-long-line
                if ('\n' == line[line_len - 1])
                    continue;
            } while (fgets(line, sizeof(line), fp));
            break;  // no more lines
        }

        if (parse_line(line))
            return -1;
    }

    fclose(fp);
    return 0;
}

/** ============================================================================
 * Returns the value from the first 'key' in the file.
------------------------------------------------------------------------------*/
int config_get_str(char **value, size_t max_len, char const *key) {
    if (!have_loaded_file)
        config_load_file();

    struct item *itm = first;

    while (itm) {
        if (!strncmp(key, itm->key, strlen(key))) {
            *value = strndup(itm->val, max_len);
            if (!(*value)) {
                LOG(LOG_ERR, "out of memory");
                return -1;
            }
            return 1;
        }
        itm = itm->next;
    }

    return 0;
}

/** ============================================================================
------------------------------------------------------------------------------*/
int config_get_int(int *val, char const *key) {
    int const MAX_LEN = 63;
    char *val_str;
    
    if (!config_get_str(&val_str, MAX_LEN, key))
        return 0;

    if (!strcmp(val_str, ""))
        return 0;

    errno = 0;
    *val = strtol(val_str, NULL, 0);
    if (errno)
        return 0;

    return 1;
}

/** ============================================================================
------------------------------------------------------------------------------*/
int config_get_bool(int *val, char const *key) {
    int const MAX_LEN = 63;
    char *val_str;
    char ch;
    
    if (!config_get_str(&val_str, MAX_LEN, key))
        return 0;

    if (!strcmp(val_str, ""))
        return 0;

    if (isalpha(ch = val_str[0]))
        ch = tolower(ch);

    if ('t' == ch  ||  'y' == ch  ||  '1' == ch) {
        *val = 1;
        return 1;
    }
    if ('f' == ch  ||  'n' == ch  ||  '0' == ch) {
        *val = 0;
        return 1;
    }

    return 0;
}
