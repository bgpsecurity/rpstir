/****************
 * The code for sending and receiving Protocol Data Units (PDUs)
 *    between server and clients
 ***************/

/*****
 * Different PDU types
 *****/
#define PDU_SERIAL_NOTIFY 0
#define PDU_SERIAL_QUERY 1
#define PDU_RESET_QUERY 2
#define PDU_CACHE_RESPONSE 3
#define PDU_IPV4_PREFIX 4
#define PDU_IPV6_PREFIX 6
#define PDU_END_OF_DATA 7
#define PDU_CACHE_RESET 8
#define PDU_ERROR_REPORT 10

/*****
 * Constants for use in the PDUs
 *****/
#define SOURCE_RPKI 0
#define SOURCE_IRR 1
#define FLAG_WITHDRAW 0
#define FLAG_ANNOUNCE 1

typedef unsigned char uchar;
typedef unsigned int uint;

/*****
 * Basic structure of a PDU
 *****/
typedef struct _PDU {
	uchar protocolVersion;
	uchar pduType;
	short color;
	uint length;
	void *typeSpecificData;
} PDU;

/*****
 * structure holding data for an IP prefix (v4 or v6)
 *****/
typedef struct _IPPrefixData {
	uchar flags;
	uchar prefixLength;
	uchar maxLength;
	uchar dataSource;
	uint ipPrefix[4];    // for ipv4, only use first entry
	uint asNumber;
} IPPrefixData;

/*****
 * read a PDU from a socket, waiting until there is data on the socket
 *   returns a NULL PDU on error
 *****/
PDU *readPDU(int sock);

/*****
 * write a PDU to a socket, returning a non-zero value for an error
 *****/
int writePDU(PDU *pdu, int sock);

/*****
 * free a PDU returned from readPDU
 *****/
void freePDU(PDU *pdu);
