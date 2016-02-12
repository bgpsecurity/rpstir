#include <assert.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "roa_utils.h"
#include "util/stringutils.h"

#define SKI_SIZE 20

// ROA_utils.h contains the headers for including these functions

// NOTE: it is assumed, when calling the address translation functions,
// that the ROA has
// been validated at entry and that ipaddrmax exceeds ipaddrmin

static int cvalhtoc2(
    unsigned char cVal,
    unsigned char *c2Array)
{
    char cHigh = 0;
    char cLow = 0;

    if (NULL == c2Array)
        return ERR_SCM_INVALARG;

    cLow = cVal & 0x0f;
    cHigh = ((cVal & 0xf0) >> 4);

    if (cLow > 0x09)
        cLow += 'A' - 10;
    else
        cLow += '0';

    if (cHigh > 0x09)
        cHigh += 'A' - 10;
    else
        cHigh += '0';

    c2Array[0] = cHigh;
    c2Array[1] = cLow;

    return 0;
}

static int cvaldtoc3(
    unsigned char cVal,
    unsigned char *c2Array,
    int *iLength)
{
    char cHigh = 0;
    char cMid = 0;
    char cLow = 0;

    if (NULL == c2Array)
        return ERR_SCM_INVALARG;

    cLow = cVal % 10;
    cHigh = cVal / 10;

    cMid = cHigh % 10;
    cHigh = cHigh / 10;

    cLow += '0';
    cMid += '0';
    cHigh += '0';

    if ('0' != cHigh)
    {
        c2Array[0] = cHigh;
        c2Array[1] = cMid;
        c2Array[2] = cLow;
        *iLength = 3;
    }
    else if ('0' != cMid)
    {
        c2Array[0] = cMid;
        c2Array[1] = cLow;
        *iLength = 2;
    }
    else
    {
        c2Array[0] = cLow;
        *iLength = 1;
    }

    return 0;
}

unsigned char *roaSKI(
    struct CMS *r)
{
    int i = 0;
    unsigned char *cSID = NULL;
    unsigned char *cReturn = NULL;
    unsigned char c2Ans[2];

    // parameter check
    if (NULL == r)
        return NULL;

    if (SKI_SIZE !=
        vsize_casn(&
                   (r->content.signedData.signerInfos.signerInfo.sid.
                    subjectKeyIdentifier)))
        return NULL;
    if (0 >
        readvsize_casn(&
                       (r->content.signedData.signerInfos.signerInfo.sid.
                        subjectKeyIdentifier), &cSID))
        return NULL;
    else
    {
        cReturn = calloc(1 + (SKI_SIZE * 3), sizeof(char));
        if (NULL == cReturn)
        {
            // free(cSID);
            return NULL;
        }
        for (i = 0; i < SKI_SIZE; i++)
        {
            cvalhtoc2(cSID[i], c2Ans);
            cReturn[(3 * i)] = c2Ans[0];
            cReturn[(3 * i) + 1] = c2Ans[1];
            cReturn[(3 * i) + 2] = ':';
        }
        // Clear the incorrectly allocated : in the last loop
        cReturn[(3 * (i - 1)) + 2] = 0x00;
        free(cSID);
        return cReturn;
    }

    return NULL;
}

unsigned char *roaSignature(
    struct CMS *r,
    int *lenp)
{
    if (r == NULL || lenp == NULL)
        return (NULL);
    *lenp = r->content.signedData.signerInfos.signerInfo.signature.lth;
    return (r->content.signedData.signerInfos.signerInfo.signature.startp);
}

static unsigned char *printIPv4String(
    unsigned char *array,
    int iArraySize,
    int iFill,
    int iPrintPrefix,
    int maxLen)
{
    int i = 0;
    unsigned char j = 0;
    int iSecLen = 0;
    int iReturnLen = 0;
    unsigned char cPrefix = 0;
    unsigned int prefix;
    unsigned char *cReturnString = NULL;
    int cReturnStringSize = 0;
    unsigned char cDecimalSection[3];

    if (NULL == array)
        return NULL;

    prefix = (8 * (iArraySize - 1)) - array[0];
    assert(prefix < 33);
    cPrefix = (uchar) prefix;
    cReturnStringSize = 30 + (3 * iArraySize);
    cReturnString = calloc(sizeof(char), cReturnStringSize);
    if (NULL == cReturnString)
        return NULL;

    for (i = 1; i < iArraySize; i++)
    {
        // If this is the last char in the array, and we're obeying DER rules
        // for the maximum in a prefix (i.e. Fill is 1), then we need to add
        // back the removed '1' bits (aka array[0])
        if ((1 == iFill) && (i == iArraySize - 1))
        {
            for (j = 0; j < array[0]; j++)
                array[i] |= (0x01 << j);
        }
        cvaldtoc3(array[i], cDecimalSection, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
        iReturnLen += iSecLen;
        // Interleaved periods (up to array maximum)
        if (4 > i)
        {
            memcpy(cReturnString + iReturnLen, ".", 1);
            iReturnLen++;
        }
    }

    if (iArraySize < 5)
    {
        for (; i < 5; i++)
        {
            if (1 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "255", 3);
                iReturnLen += 3;
            }
            else if (0 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "0", 1);
                iReturnLen++;
            }
            // Interleaved periods (continued)
            if (4 > i)
            {
                memcpy(cReturnString + iReturnLen, ".", 1);
                iReturnLen++;
            }
        }
    }

    // If we're printing prefixes, we need the array to either not be
    // full length or to have unused bits mentioned in array[0]
    if ((cTRUE == iPrintPrefix) && (32 != cPrefix))
    {
        memcpy(cReturnString + iReturnLen, "/", 1);
        iReturnLen++;
        cvaldtoc3(cPrefix, cDecimalSection, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
        iReturnLen += iSecLen;
        if (maxLen)
        {
            char maxlenbuf[10];
            memset(maxlenbuf, 0, sizeof(maxlenbuf));
            sprintf(maxlenbuf, "^%d-%d", prefix, maxLen);
            assert(iReturnLen + (int)strlen(maxlenbuf) < cReturnStringSize);
            strcpy((char *)&cReturnString[iReturnLen], maxlenbuf);
            iReturnLen += strlen(maxlenbuf);
        }
    }

    return cReturnString;
}

static unsigned char *printIPv6String(
    unsigned char *array,
    int iArraySize,
    int iFill,
    int iPrintPrefix,
    int maxLen)
{
    int i = 0;
    unsigned char j = 0;
    int iSecLen = 0;
    int iReturnLen = 0;
    unsigned int prefix;
    unsigned char cPrefix = 0;
    unsigned char *cReturnString = NULL;
    unsigned char cHexSection[2];
    int cReturnStringSize = 0;
    unsigned char cDecimalPrefix[3];

    if (NULL == array)
        return NULL;

    prefix = 8 * (iArraySize - 1) - array[0];
    assert(prefix < 129);
    cPrefix = (uchar) prefix;
    cReturnStringSize = 60 + (3 * iArraySize);
    cReturnString = calloc(sizeof(char), cReturnStringSize);
    if (NULL == cReturnString)
        return NULL;

    for (i = 1; i < iArraySize; i++)
    {
        // If this is the last char in the array, and we're obeying DER rules
        // for the maximum in a prefix (i.e. Fill is 1), then we need to add
        // back the removed '1' bits in the prefix (array[0])
        if ((1 == iFill) && (i == iArraySize - 1))
        {
            for (j = 0; j < array[0]; j++)
                array[i] |= (0x01 << j);
        }
        cvalhtoc2(array[i], cHexSection);
        memcpy(cReturnString + iReturnLen, cHexSection, 2);
        iReturnLen += 2;
        // Interleaved colons
        if ((16 > i) && (0 == i % 2))
        {
            memcpy(cReturnString + iReturnLen, ":", 1);
            iReturnLen++;
        }
    }
    if (iArraySize < 17)
    {
        for (; i < 17; i++)
        {
            if (1 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "FF", 2);
                iReturnLen += 2;
            }
            else if (0 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "00", 2);
                iReturnLen += 2;
            }
            // Every other translated byte needs a colon
            if ((16 > i) && (0 == i % 2))
            {
                memcpy(cReturnString + iReturnLen, ":", 1);
                iReturnLen++;
            }
        }
    }

    // If we're printing prefixes, we need the array to either not be
    // full length or to have unused bits mentioned in array[0]
    if ((cTRUE == iPrintPrefix) && (128 != cPrefix))
    {
        memcpy(cReturnString + iReturnLen, "/", 1);
        iReturnLen++;
        cvaldtoc3(cPrefix, cDecimalPrefix, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalPrefix, iSecLen);
        iReturnLen += iSecLen;
        if (maxLen)
        {
            char maxlenbuf[10];
            memset(maxlenbuf, 0, sizeof(maxlenbuf));
            sprintf(maxlenbuf, "^%d-%d", prefix, maxLen);
            assert(iReturnLen + (int)strlen(maxlenbuf) < cReturnStringSize);
            strcpy((char *)&cReturnString[iReturnLen], maxlenbuf);
            iReturnLen += strlen(maxlenbuf);
        }
    }

    return cReturnString;
}

static unsigned char *roaIPAddr(
    struct ROAIPAddress *raddr,
    int iFamily)
{
    int iSize = 0,
        maxLen;
    unsigned char *cASCIIString = NULL,
        ipaddr[200];

    // parameter check
    if ((NULL == raddr) || (0 == iFamily))
        return NULL;

    memset(ipaddr, 0, sizeof(ipaddr));
    iSize = vsize_casn(&raddr->address);

    if ((0 >= iSize) || ((int)sizeof(ipaddr) < iSize))
        return NULL;
    if (0 > read_casn(&raddr->address, ipaddr))
        return NULL;
    if (read_casn_num(&raddr->maxLength, (long *)(&maxLen)) == 0)
        maxLen = 0;
    if (IPV4 == iFamily)
    {
        cASCIIString = printIPv4String(ipaddr, iSize, 0, cTRUE, maxLen);
    }
    else if (IPV6 == iFamily)
    {
        cASCIIString = printIPv6String(ipaddr, iSize, 0, cTRUE, maxLen);
    }

    return cASCIIString;
}

static unsigned char **roaIPAddresses(
    struct ROAIPAddressFamily *roapAddrFam,
    int *numOfAddresses)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamily = 0;
    int iAddrs = 0;
    unsigned char **pcAddresses = NULL;
    unsigned char family[3];

    struct ROAIPAddress *rIPAddr = NULL;

    // parameter check
    if ((NULL == roapAddrFam) || (NULL == numOfAddresses))
        return NULL;

    iRes = read_casn(&(roapAddrFam->addressFamily), family);
    if (0 > iRes)
        return NULL;

    if (0x01 == family[1])
        iFamily = IPV4;
    else if (0x02 == family[1])
        iFamily = IPV6;
    else
        return NULL;

    iAddrs = num_items(&(roapAddrFam->addresses.self));

    if (0 >= iAddrs)
        return NULL;

    pcAddresses = (unsigned char **)calloc(iAddrs, sizeof(char **));
    if (NULL == pcAddresses)
        return NULL;

    for (i = 0; i < iAddrs; i++)
    {
        rIPAddr =
            (struct ROAIPAddress *)member_casn(&(roapAddrFam->addresses.self),
                                               i);
        pcAddresses[i] = roaIPAddr(rIPAddr, iFamily);
        if (NULL == pcAddresses[i])
        {
            for (j = i - 1; j >= 0; j--)
                free(pcAddresses[j]);
            free(pcAddresses);
            return NULL;
        }
    }

    *numOfAddresses = iAddrs;
    return pcAddresses;
}

/**
    WARNING: This function does no error checking. Calling it with a NULL
    r, or if r hasn't passed roaValidate() could cause unpredictable
    behavior.
*/
uint32_t roaAS_ID(
    struct CMS *r)
{
    intmax_t iAS_ID;
    read_casn_num_max(&r->content.signedData.encapContentInfo.eContent.roa.asID,
                      &iAS_ID);

    return (uint32_t)iAS_ID;
}

ssize_t roaGetPrefixes(
    struct CMS *rp,
    struct roa_prefix * * prefixes)
{
    struct ROAIPAddrBlocks *addrBlocksp =
        &rp->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks;
    struct ROAIPAddressFamily *famp;

    // Actual length of *prefixes
    size_t prefixes_length = 0;

    // Allocated length of *prefixes.  Start small, but big enough to
    // avoid most reallocations.
    size_t prefixes_allocated = 16;

    *prefixes = malloc(prefixes_allocated * sizeof(struct roa_prefix));
    if (*prefixes == NULL)
    {
        return ERR_SCM_NOMEM;
    }

    for (famp =
         (struct ROAIPAddressFamily *)member_casn(&addrBlocksp->self, 0); famp;
         famp = (struct ROAIPAddressFamily *)next_of(&famp->self))
    {
        // first two bytes are AFI in network byte order, third byte
        // is the optional SAFI, fourth byte is ???
        uchar famtyp[4];
        // min length of AFI/SAFI is 2
        if (read_casn(&famp->addressFamily, famtyp) < 2)
        {
            free(*prefixes);
            *prefixes = NULL;
            return -1;
        }

        uint_fast16_t afi = ((uint_fast16_t)famtyp[0] << 8) + famtyp[1];
        uint_fast8_t prefix_family_length;
        switch (afi)
        {
            case 1:
                prefix_family_length = 4;
                break;

            case 2:
                prefix_family_length = 16;
                break;

            default:
                free(*prefixes);
                *prefixes = NULL;
                return -1;
        }

        struct ROAIPAddress *ipaddressp;
        for (ipaddressp =
             (struct ROAIPAddress *)member_casn(&famp->addresses.self, 0);
             ipaddressp;
             ipaddressp = (struct ROAIPAddress *)next_of(&ipaddressp->self))
        {
            if (prefixes_length >= prefixes_allocated)
            {
                prefixes_allocated *= 2;

                struct roa_prefix * new_prefixes = realloc(
                    *prefixes,
                    prefixes_allocated * sizeof(struct roa_prefix));
                if (new_prefixes == NULL)
                {
                    free(*prefixes);
                    *prefixes = NULL;
                    return ERR_SCM_NOMEM;
                }
                *prefixes = new_prefixes;
            }

            (*prefixes)[prefixes_length].prefix_family_length =
                prefix_family_length;

            // Buffer for a single IP prefix, stored as a BIT STRING.
            // The first byte will hold the number of unused (padding)
            // bits in the last byte.
            /**
             * \todo change the magic 16 to a symbolic constant (it's
             * the maximum address length of all supported address
             * families, in bytes)
             */
            uint8_t prefix_buf[1+16];

            int prefix_buflen =
                read_casn(&ipaddressp->address, prefix_buf);
            memset((*prefixes)[prefixes_length].prefix, 0,
                prefix_family_length);
            memcpy((*prefixes)[prefixes_length].prefix,
                prefix_buf + 1, prefix_buflen - 1);

            (*prefixes)[prefixes_length].prefix_length =
                ((prefix_buflen - 1) * 8) - prefix_buf[0];

            int vsize = vsize_casn(&ipaddressp->maxLength);
            if (vsize < 0)
            {
                free(*prefixes);
                *prefixes = NULL;
                return -1;
            }
            else if (vsize > 0)
            {
                long prefix_max_length;
                read_casn_num(&ipaddressp->maxLength,
                    &prefix_max_length);
                (*prefixes)[prefixes_length].prefix_max_length =
                    prefix_max_length;
            }
            else
            {
                // Default max length is equal to the prefix length
                (*prefixes)[prefixes_length].prefix_max_length =
                    (*prefixes)[prefixes_length].prefix_length;
            }

            ++prefixes_length;
        }
    }

    return prefixes_length;
}

err_code
roaGenerateFilter(
    struct CMS *r,
    uchar *cert,
    FILE *fp,
    char *str,
    int strLen)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamilies = 0;
    int iAddrNum = 0;
    uint32_t iAS_ID = 0;
    int sta;
    char cAS_ID[17];
    unsigned char *cSID = NULL;
    unsigned char **pcAddresses = NULL;
    struct ROAIPAddressFamily *roaFamily = NULL;

    // for local use, for brevity
    struct casn *ipblocks =
        &r->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks.self;

    UNREFERENCED_PARAMETER(cert);
    // parameter check
    if (NULL == fp && NULL == str)
        return ERR_SCM_INVALARG;

    memset(cAS_ID, 0, 17);
    iAS_ID = roaAS_ID(r);
    sta = snprintf(cAS_ID, sizeof(cAS_ID), "%" PRIu32, iAS_ID);
    if (sta < 0 || sta >= (int)sizeof(cAS_ID))
        return ERR_SCM_UNSPECIFIED;

    cSID = roaSKI(r);
    if (NULL == cSID)
        return ERR_SCM_INVALSKI;

    // For each family, print out all triplets beginning with SKI and AS#
    // and ending with each IP address listed in the ROA
    iFamilies = num_items(ipblocks);
    for (i = 0; i < iFamilies; i++)
    {
        roaFamily = (struct ROAIPAddressFamily *)member_casn(ipblocks, i);
        if (NULL == roaFamily)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        pcAddresses = roaIPAddresses(roaFamily, &iAddrNum);
        if (NULL == pcAddresses)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }

        for (j = 0; j < iAddrNum; j++)
        {
            if (str != NULL)
            {
                xsnprintf(str, strLen, "%s %s %s\n",
                          cSID, cAS_ID, pcAddresses[j]);
                strLen -= strlen(str);
                str += strlen(str);
            }
            if (fp != NULL)
            {
                iRes = fprintf(fp, "%s %s %s\n", cSID, cAS_ID, pcAddresses[j]);
                if (0 > iRes)
                    return ERR_SCM_BADFILE;
            }
        }
        for (j = iAddrNum - 1; j >= 0; j--)
            free(pcAddresses[j]);
        free(pcAddresses);
        pcAddresses = NULL;
    }

    free(cSID);
    return 0;
}

int roaGenerateFilter2(
    struct CMS *r,
    char **strpp)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamilies = 0;
    int iAddrNum = 0;
    uint32_t iAS_ID = 0;
    int sta;
    char cAS_ID[20];
    unsigned char *cSID = NULL;
    unsigned char **pcAddresses = NULL;
    struct ROAIPAddressFamily *roaFamily = NULL;

    // for local use, for brevity
    struct casn *ipblocks =
        &r->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks.self;

    // parameter check
    if (*strpp != NULL)
        free(*strpp);

    memset(cAS_ID, 0, sizeof(cAS_ID));
    iAS_ID = roaAS_ID(r);
    sta = snprintf(cAS_ID, sizeof(cAS_ID), "%" PRIu32, iAS_ID);
    if (sta < 0 || sta >= (int)sizeof(cAS_ID))
        return -1;

    if ((cSID = roaSKI(r)) == NULL)
        return ERR_SCM_INVALSKI;

#define FILTER_INCR 1024
    int strLen,
        remLen;
    char *rstrp,
       *strp;
    rstrp = strp = (char *)calloc(1, FILTER_INCR);
    strLen = remLen = FILTER_INCR;
    // For each family, print out all triplets beginning with SKI and AS#
    // and ending with each IP address listed in the ROA
    iFamilies = num_items(ipblocks);
    for (i = 0; i < iFamilies; i++)
    {
        if ((roaFamily = (struct ROAIPAddressFamily *)member_casn(ipblocks, i))
            == NULL)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        if ((pcAddresses = roaIPAddresses(roaFamily, &iAddrNum)) == NULL)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        for (j = 0; j < iAddrNum; j++)
        {
            while ((iRes = snprintf(rstrp, remLen, "%s %s %s\n", cSID, cAS_ID,
                                    pcAddresses[j])) >= remLen)
            {
                int used = rstrp - strp;
                strp = (char *)realloc(strp, strLen += FILTER_INCR);
                rstrp = &strp[used];
                remLen += FILTER_INCR;
            }
            if (iRes < 0)
            {
                abort();
            }

            remLen -= strlen(rstrp);
            rstrp += strlen(rstrp);
        }
        for (j = iAddrNum - 1; j >= 0; j--)
            free(pcAddresses[j]);
        free(pcAddresses);
        pcAddresses = NULL;
    }

    free(cSID);
    *strpp = strp;
    return 0;
}
