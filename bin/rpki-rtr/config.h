#ifndef _RTR_CONFIG_H
#define _RTR_CONFIG_H

#include <syslog.h>

#define RTR_LOG_IDENT PACKAGE_NAME "-rtrd"
#define RTR_LOG_FACILITY LOG_DAEMON

#define LISTEN_PORT "1234"

#define MAIN_LOOP_INTERVAL 5

#define DB_RESPONSE_BUFFER_LENGTH 3
#define DB_ROWS_PER_RESPONSE 1024
#define DB_INITIAL_THREADS 8

/*
 * Quote from draft-ietf-sidr-rpki-rtr-19, Section 6.2: The cache MUST rate
 * limit Serial Notifies to no more frequently than one per minute. 
 */
#define CXN_NOTIFY_INTERVAL 60

// How often to check the cache state when more than CXN_NOTIFY_INTERVAL
// has elapsed without sending a Serial Notify.
#define CXN_CACHE_STATE_INTERVAL 10

// The largest PDU should be an error report PDU.
// The second largest is an IPv6 prefix at 32 bytes.
// Error report PDUs MUST NOT contain other error report PDUs,
// so the largest error report PDU is 8 (header) + 4 (field length)
// + 32 (IPv6 prefix PDU) + 4 (field length) + length of error text
// = 48 + length of error text. I.e. 1024 should almost definitely
// be large enough and is probably significantly larger than necessary.
#define MAX_PDU_SIZE 1024

// The maximum number of listening sockets to support.
// Each one is only sizeof(int) large and isn't stored
// in many places, so it seems easier to pick a limit than
// to bother with dynamic storage. It shouldn't be hard to
// switch to dynamic storage later if needed.
#define MAX_LISTENING_SOCKETS 64

// Lengths for strings of hosts and services.
#define MAX_HOST_LENGTH 256
#define MAX_SERVICE_LENGTH 16


#endif
