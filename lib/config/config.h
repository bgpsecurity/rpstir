#ifndef _LIB_CONFIG_CONFIG_H
#define _LIB_CONFIG_CONFIG_H


#include "configlib/configlib.h"


enum config_key {
    CONFIG_ROOT,                // $RPKI_ROOT
    // CONFIG_PROCESS_PORT, // $RPKI_PORT
    // CONFIG_DATABASE, // $RPKI_DB
    // CONFIG_DATABASE_USER, // $RPKI_DBUSER
    // CONFIG_DATABASE_PASSWORD, // $RPKI_DBPASS
    // CONFIG_DATABASE_ROOT_PASSWORD, // $RPKI_ROOTPASS
    // CONFIG_DOWNLOAD_THREADS, // $RPKI_TCOUNT
    // CONFIG_RSYNC_LISTEN_PORT, // $RPKI_LISTPORT
    // CONFIG_DSN, // $RPKI_DSN

    CONFIG_NUM_OPTIONS
};


/**
 * Wrapper around config_load() with rpstir-specific data.
 */
bool my_config_load(
    );


#endif
