#ifndef _LIB_CONFIG_CONFIG_H
#define _LIB_CONFIG_CONFIG_H


#include "configlib/configlib.h"


enum config_key {
    CONFIG_ROOT_DIR,
    CONFIG_RPKI_PORT,
    CONFIG_DATABASE,
    CONFIG_DATABASE_USER,
    CONFIG_DATABASE_PASSWORD,
    CONFIG_DATABASE_ROOT_PASSWORD,
    CONFIG_DATABASE_DSN,
    CONFIG_DOWNLOAD_CONCURRENCY,
    CONFIG_RSYNC_LISTEN_PORT,
    CONFIG_RPKI_RTR_RETENTION_HOURS,

    CONFIG_NUM_OPTIONS
};


/**
 * Wrapper around config_load() with rpstir-specific data.
 */
bool my_config_load(
    );


#endif
