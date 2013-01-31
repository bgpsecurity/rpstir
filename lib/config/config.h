#ifndef _LIB_CONFIG_CONFIG_H
#define _LIB_CONFIG_CONFIG_H


#include <inttypes.h>
#include <stdbool.h>

#include "configlib/configlib.h"


/**
    This is the only file that needs to be directly included to use rpstir's
    configuration system. See lib/configlib/configlib.h for more detail about
    extending the configuration system.

    For a quick introduction, here's an example program that uses this
    library to print out the database. Note that this example does do all
    necessary error checking.

        #include <stdio.h>
        #include <stdlib.h>
        #include "util/logging.h"
        #include "config/config.h"

        static void print_database()
        {
            printf("database: %s\n", CONFIG_DATABASE_get());
        }

        int main()
        {
            OPEN_LOG("foobar", LOG_USER);

            if (!my_config_load())
            {
                LOG(LOG_ERR, "failed to load configuration");
                return EXIT_FAILURE;
            }

            print_database();

            config_unload();

            CLOSE_LOG();

            return EXIT_SUCCESS;
        }

    To add a new option:

        1. Add the key to enum config_key below.
        2. Define the helper functions below using one of the helper macros
           (e.g. CONFIG_GET_HELPER). See lib/configlib/configlib.h for a
           description of the available helper macros.
        3. Add the option's description to the config_options array in
           lib/config/config.c. See struct config_option in
           lib/configlib/configlib.h and the types in lib/configlib/types/ for
           more information.
*/


enum config_key {
    CONFIG_RPKI_PORT,
    CONFIG_DATABASE,
    CONFIG_DATABASE_USER,
    CONFIG_DATABASE_PASSWORD,
    CONFIG_DATABASE_ROOT_PASSWORD,
    CONFIG_DATABASE_DSN,
    CONFIG_TRUST_ANCHOR_LOCATORS,
    CONFIG_LOG_LEVEL,
    CONFIG_DOWNLOAD_CONCURRENCY,
    CONFIG_RPKI_RTR_RETENTION_HOURS,
    CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN,
    CONFIG_RPKI_ALLOW_NO_MANIFEST,
    CONFIG_RPKI_ALLOW_STALE_CRL,
    CONFIG_RPKI_ALLOW_STALE_MANIFEST,
    CONFIG_RPKI_ALLOW_NOT_YET,
    CONFIG_RPKI_EXTRA_PUBLICATION_POINTS,
    CONFIG_NEW_VERSION_CHECK,
    CONFIG_NEW_VERSION_CHECK_CA_CERT,
    CONFIG_TEMPLATE_CA_CERT,
    CONFIG_TEMPLATE_EE_CERT,
    CONFIG_TEMPLATE_CRL,
    CONFIG_TEMPLATE_MANIFEST,
    CONFIG_TEMPLATE_ROA,
    CONFIG_RPKI_CACHE_DIR,
    CONFIG_LOG_DIR,

    CONFIG_NUM_OPTIONS
};


/**
    The below macro calls generate helper functions to access the configuration
    values. See the definitions of each macro in lib/configlib/configlib.h for
    more detail, but here's a summary of how to access some of the below
    options:

        const char * database = CONFIG_DATABASE_get();

        uint16_t rpki_port = CONFIG_RPKI_PORT_get();

        for (size_t i = 0;
            i < config_get_length(CONFIG_RPKI_EXTRA_PUBLICATION_POINTS);
            ++i)
        {
            const char * rpki_extra_pub_pt =
                CONFIG_RPKI_EXTRA_PUBLICATION_POINTS_get(i);
            printf("extra publication point: %s\n", rpki_extra_pub_pt);
        }
*/

CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_PORT, uint16_t)
CONFIG_GET_HELPER(CONFIG_DATABASE, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_USER, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_PASSWORD, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_ROOT_PASSWORD, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_DSN, char)
CONFIG_GET_ARRAY_HELPER(CONFIG_TRUST_ANCHOR_LOCATORS, char)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_LOG_LEVEL, int)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_DOWNLOAD_CONCURRENCY, size_t)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_RTR_RETENTION_HOURS, size_t)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_NO_MANIFEST, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_CRL, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_MANIFEST, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_NOT_YET, bool)
CONFIG_GET_ARRAY_HELPER(CONFIG_RPKI_EXTRA_PUBLICATION_POINTS, char)
CONFIG_GET_HELPER(CONFIG_NEW_VERSION_CHECK, char)
CONFIG_GET_HELPER(CONFIG_NEW_VERSION_CHECK_CA_CERT, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_CA_CERT, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_EE_CERT, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_CRL, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_MANIFEST, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_ROA, char)
CONFIG_GET_HELPER(CONFIG_RPKI_CACHE_DIR, char)
CONFIG_GET_HELPER(CONFIG_LOG_DIR, char)



/**
    Wrapper around config_load() with rpstir-specific data.

    The notes about thread-safety and logging from config_load() in
    lib/configlib/configlib.h apply to this too.

    If you set the environment variable with the name defined by CONFIG_ENV_VAR
    in configure.ac (currently $RPSTIR_CONFIG), this function will use that as
    a file to load configuration from. This allows users to try out one-time
    configuration changes and test programs to use their own configuration. In
    test scripts, consider using the shell function use_config_file() in
    tests/test.include(.in).

    See also config_unload() in configlib.h.
*/
bool my_config_load(
    );


#endif
