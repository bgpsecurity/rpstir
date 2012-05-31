#ifndef _CONFIG_H
#define _CONFIG_H

#include <inttypes.h>

enum config_key {
	CONFIG_ROOT, // $RPKI_ROOT
	CONFIG_PROCESS_PORT, // $RPKI_PORT
	CONFIG_DATABASE, // $RPKI_DB
	CONFIG_DATABASE_USER, // $RPKI_DBUSER
	CONFIG_DATABASE_PASSWORD, // $RPKI_DBPASS
	CONFIG_DATABASE_ROOT_PASSWOR, // $RPKI_ROOTPASS
	CONFIG_DOWNLOAD_THREADS, // $RPKI_TCOUNT
	CONFIG_RSYNC_LISTEN_PORT, // $RPKI_LISTPORT
	CONFIG_DSN, // $RPKI_DSN

	CONFIG_NUM_ITEMS
};

/** Return the value for a non-array config option. */
const void * config_get(size_t key);

/** Return the length of an array config option. */
size_t config_get_length(size_t key);

/** Return the values for an array config option. */
void const * const * config_get_array(size_t key);

/**
	Load configuration data from a config file.

	@param filename	The file to load data from. If this is NULL, the
			default configuration file is used.
*/
bool config_load(const char * filename);

/**
	Call this after configuration data is no longer needed to free resources.

	This is usually only called before a program exits.
*/
void config_unload();

#endif
