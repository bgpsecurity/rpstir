#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "inet.h"


#define CVTV_BODY_COMMON(addrstrlen, ip_type, number_func, separators, family) \
    char ipstr[addrstrlen]; \
    ip_type ipbin0, ipbin1; \
    size_t i, j; \
    size_t prefix_len; \
    int consumed; \
    \
    if (ip == NULL || buf == NULL) \
        return -1; \
    \
    for (i = 0; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
    \
    j = 0; \
    for (; \
        ip[i] != '\0' && j + 1 < sizeof(ipstr) && \
            (number_func((int)(unsigned char)ip[i]) || strchr(separators, ip[i]) != NULL); \
        ++i) \
    { \
        ipstr[j++] = ip[i]; \
    } \
    ipstr[j] = '\0'; \
    \
    if (inet_pton(family, ipstr, &ipbin0) != 1) \
        return -1; \
    \
    for (; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
    \
    switch (ip[i]) \
    { \
        case '\0': \
            /* single IP, no prefix */ \
            memcpy(buf, &ipbin0, sizeof(ipbin0)); \
            return 0; \
        \
        case '/': \
            /* CIDR notation */ \
            memcpy(buf, &ipbin0, sizeof(ipbin0)); \
            for (++i; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
            if (sscanf(&ip[i], "%zu%n", &prefix_len, &consumed) < 1) \
                return -1; \
            if (prefix_len > sizeof(ipbin0) * 8) \
                return -1; \
            for (i += consumed; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
            if (ip[i] != '\0') \
                return -1; \
            if (fill == 0x00) \
            { \
                if (prefix_len % 8 != 0) \
                { \
                    buf[prefix_len / 8] &= 0xFF << (8 - prefix_len % 8); \
                    j = prefix_len / 8 + 1; \
                } \
                else \
                { \
                    j = prefix_len / 8; \
                } \
                memset(&buf[j], 0, sizeof(ipbin0) - j); \
            } \
            else if (fill == 0xFF) \
            { \
                if (prefix_len % 8 != 0) \
                { \
                    buf[prefix_len / 8] |= 0xFF >> (prefix_len % 8); \
                    j = prefix_len / 8 + 1; \
                } \
                else \
                { \
                    j = prefix_len / 8; \
                } \
                memset(&buf[j], 0xFF, sizeof(ipbin0) - j); \
            } \
            else \
            { \
                return -1; \
            } \
            return 0; \
        \
        case '-': \
            /* range */ \
            for (++i; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
            j = 0; \
            for (; \
                ip[i] != '\0' && j + 1 < sizeof(ipstr) && \
                    (number_func((int)(unsigned char)ip[i]) || strchr(separators, ip[i]) != NULL); \
                ++i) \
            { \
                ipstr[j++] = ip[i]; \
            } \
            ipstr[j] = '\0'; \
            if (inet_pton(family, ipstr, &ipbin1) != 1) \
                return -1; \
            for (; ip[i] != '\0' && isspace((int)(unsigned char)ip[i]); ++i); \
            if (ip[i] != '\0') \
                return -1; \
            if (memcmp(&ipbin0, &ipbin1, sizeof(ipbin0)) > 0) \
                return -1; \
            if (fill == 0x00) \
            { \
                memcpy(buf, &ipbin0, sizeof(ipbin0)); \
            } \
            else if (fill == 0xFF) \
            { \
                memcpy(buf, &ipbin1, sizeof(ipbin1)); \
            } \
            else \
            { \
                return -1; \
            } \
            return 0; \
        \
        default: \
            return -1; \
    }

int cvtv4(
    uint8_t fill,
    const char *ip,
    uint8_t * buf)
{
    CVTV_BODY_COMMON(INET_ADDRSTRLEN, struct in_addr,
                     isdigit,
                     ".",
                     AF_INET)
}

int cvtv6(
    uint8_t fill,
    const char *ip,
    uint8_t * buf)
{
    CVTV_BODY_COMMON(INET6_ADDRSTRLEN, struct in6_addr,
                     isxdigit,
                     ":.",
                     AF_INET6)
}

#undef CVTV_BODY_COMMON
