#ifndef _RTR_CONFIG_H
#define _RTR_CONFIG_H


#define LOG_FILE "rtrd.log"
#define LOG_FACILITY "rtrd"

#define LISTEN_PORT 1234

#define MAIN_LOOP_INTERVAL 5

#define DB_RESPONSE_BUFFER_LENGTH 3
#define DB_INITIAL_THREADS 8

/*
Quote from draft-ietf-sidr-rpki-rtr-19, Section 6.2:
	The cache MUST rate limit Serial Notifies to no more frequently
	than one per minute.
*/
#define CXN_CACHE_STATE_INTERVAL 60

// The largest PDU should be an error report PDU.
// The second largest is an IPv6 prefix at 32 bytes.
// Error report PDUs MUST NOT contain other error report PDUs,
// so the largest error report PDU is 8 (header) + 4 (field length)
// + 32 (IPv6 prefix PDU) + 4 (field length) + length of error text
// = 48 + length of error text. I.e. 1024 should almost definitely
// be large enough and is probably significantly larger than necessary.
#define MAX_PDU_SIZE 1024


#endif
