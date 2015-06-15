#ifndef _UTIL_INET_H
#define _UTIL_INET_H

#include <inttypes.h>

/**
 * Convert a string representation of an IPv4 range to a single address.
 *
 * @param fill 0x00 indicates to return the lower end of the range,
 *             0xff indicates to return the upper end.
 * @param ip String of a single IP, CIDR notation, or a range of the form "ip1-ip2".
 * @param buf Where to write the output IP address, in network encoding.
 */
int cvtv4(
    uint8_t fill,
    const char *ip,
    uint8_t * buf);

/**
 * See cvtv4() above. This is equivalent, but for IPv6 addresses.
 */
int cvtv6(
    uint8_t fill,
    const char *ip,
    uint8_t * buf);

#endif
