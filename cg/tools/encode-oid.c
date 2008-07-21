#include <stdio.h>
#include <string.h>

#define MAX_UINT64_EXPANSION            9
#define MAX_LDAP_OID_BYTES              128
#define MIN_ASN1_BUF_LEN                3
#define OIT_TOP_FACTOR                  40L
#define MAX_OIT_TOP                     2L
#define MAX_ULONG                       0xFFFFFFFFL
#define LBER_OID                        6
#define BASE_TEN                        10
#define ERR_INVALID_IDENTITY            -677
#define ERR_INSUFFICIENT_BUFFER         -649

typedef unsigned long uint32;

int LdapOid2Asn1Id(char *ldapOid, int asn1BufLen, char *asn1Buf);
int Asn1Id2LdapOid(uint32 asn1Len, char *asn1Id, int oidBufLen, char *oidBuf);
int GetKeyboardInput(int inputBufLen, char *inputBuf);

int main(int argc, char *argv[])
{
    int err, i, encodedLen;
    char inputBuf[80];
    char buf1[128];
    char buf2[MAX_LDAP_OID_BYTES + 1];

    while (argc-- > 1)
    {
        if ((err = LdapOid2Asn1Id(*++argv, sizeof(buf1), buf1)) != 0)
        {
            printf("LdapOid2Asn1Id failure:%d.\n", err);
	    continue;
        }

        encodedLen = buf1[1] + 2;            /* Add for the beginning two fields. */
        for (i = 0; i < encodedLen; i++)
            printf("%02x ", (unsigned char)buf1[i]);

        printf("\n");
    }

    return err;
}


int LdapOid2Asn1Id(char *ldapOid, int asn1BufLen, char *asn1Buf)
{
    char *startp, *endp;
    unsigned long value, mod, oitTop;
    int err, offset, i, j;
    char tempBuf[MAX_UINT64_EXPANSION];

    endp = ldapOid;
    err = 0;
    i = 0;

    if (ldapOid == NULL)
    {
        printf("LdapOid2Asn1Id: passed NULL ldapOid.\n");
        return ERR_INVALID_IDENTITY;
    }

    if ((asn1BufLen < MIN_ASN1_BUF_LEN) || (asn1Buf == NULL))
    {
        return ERR_INSUFFICIENT_BUFFER;
    }

    do
    {
        startp = endp;
        if (isdigit(*startp) == 0)
        {
            offset = startp - ldapOid;                 /* Numerals only. */
        }
        else if ((*startp == '0')  &&
                ((*(startp + 1) != '.') && (*(startp + 1) != '\0')))
        {
            offset = (startp + 1) - ldapOid;           /* Single 0s only. */
        }
        else
        {
            offset = -1;                               /* So far, so good. */
        }

        if (offset >= 0)
        {
            printf("LdapOid2Asn1Id: invalid OID syntax '%c' at offset %d.\n",
                    ldapOid[offset], offset);
            err = ERR_INVALID_IDENTITY;
            break;
        }

        value = strtoul(startp, &endp, BASE_TEN);
        if (value == MAX_ULONG)
        {

		
            printf("LdapOid2Asn1Id: "
                    "overflow failure on huge integer element at offset %d.\n",
                    startp - ldapOid);
            err = ERR_INVALID_IDENTITY;
            break;
        }

        if ((*endp == '.') && (*(endp + 1) != '\0'))
        {
            endp++;
        }

        if (i > 2)
        {
            /* Do this the 3rd-nth time through the main
             * loop for every integer element in the OID.
             */

            /* First, unravel the element backwards. */
            j = 0;
            while (value >= 0x80L)
            {
                mod = value % 0x80L;
                tempBuf[j++] = (char)mod;
                value = (value - mod) / 0x80L;
            }
            tempBuf[j] = (char)value;

            if ((i + j) >= asn1BufLen)
            {
                printf("LdapOid2Asn1Id: output buffer len %d is too small.\n",
                        asn1BufLen);
                err = ERR_INSUFFICIENT_BUFFER;
                break;
            }

            /* Then, put the unraveled octets in the proper ASN.1 order. */
            while (j > 0)
            {
                asn1Buf[i++] = tempBuf[j--] | 0x80;
            }
            asn1Buf[i++] = tempBuf[j];
        }
        else if (i == 2)
        {
            /* Only do this the 2nd time through the main loop. */
            if (value >= OIT_TOP_FACTOR)
            {
                printf("LdapOid2Asn1Id: "
                        "2nd OID integer '%d' must be less than %d.\n",
                        value, OIT_TOP_FACTOR);
                err = ERR_INVALID_IDENTITY;
                break;
            }
            asn1Buf[i++] = (char)((oitTop * OIT_TOP_FACTOR) + value);
        }
        else
        {


            /* Only do this the 1st time through the main loop. */
            i = 2;
            oitTop = value;
            if (oitTop > MAX_OIT_TOP)
            {
                printf("LdapOid2Asn1Id: 1st OID integer '%d' must be either "
                        "0, 1 or 2.\n", oitTop);
                err = ERR_INVALID_IDENTITY;
                break;
            }
        }
    } while (*endp != '\0');

    if ((i <= 3) && (err == 0))
    {
        err = ERR_INVALID_IDENTITY;
        printf("LdapOid2Asn1Id: LDAP OIDs must contain at least 3 elements.\n");
    }

    if (err == 0)
    {
        asn1Buf[0] = LBER_OID;
        asn1Buf[1] = i - 2;
    }
    else
    {
        asn1Buf[0] = '\0';
    }

    return err;
}


/* This handles Asn1Ids with a length of 127 or less.
 * NW4&5 Asn1Ids seem to be limited to 32 bytes max.
 */
int Asn1Id2LdapOid(uint32 asn1Len, char *asn1Id, int oidBufLen, char *oidBuf)
{
    unsigned long value;
    int err, length, i, index;
    char *cur;

    err = 0;
    i = 0;
    index = 0;

    if ((oidBufLen <= MAX_LDAP_OID_BYTES) || (oidBuf == NULL))
    {
        return ERR_INSUFFICIENT_BUFFER;
    }

    /* NW stores a 32 byte array of zeros when there is no OID ??? */
    if ((asn1Len == 0) || (asn1Id == NULL) || (asn1Id[0] == '\0'))
    {
        goto _Asn1Id2LdapOidExit;
    }

    value = (unsigned long)(asn1Id[i++]);
    if (value != LBER_OID)
    {

        printf("Asn1Id2LdapOid: 1st ASN.1 value %d must be %d.\n",
                value, LBER_OID);
        err = ERR_INVALID_IDENTITY;
        goto _Asn1Id2LdapOidExit;
    }

    length = (int)(asn1Id[i++]);
    if ((length > 127) || (length < 2))
    {
        printf("Asn1Id2LdapOid: ASN.1 length %d must be between 2 and 127.\n",
                length);
        err = ERR_INVALID_IDENTITY;
        goto _Asn1Id2LdapOidExit;
    }

    /* The first element after the length contains 2 oid values. */
    value = ((unsigned long)(asn1Id[i])) / 40;        /* First value. */
    index += sprintf(&(oidBuf[index]), "%lu", value);

    value = ((unsigned long)(asn1Id[i++])) % 40;        /* Secound value. */
    index += sprintf(&(oidBuf[index]), ".%lu", value);

    /* Now adjust everything for the rest of the asn1Id. */
    cur = &asn1Id[i];
    length--;
    i = 0;

    /* This code converts base 128 numbers to decimal. */
    while (i < length)
    {
        value  = 0L;

        /* Make sure we have enough space for the next series of:
         * a delimeter char, an unsigned long decimal, and a null terminator.
         */
        if ((index + 1 + (sizeof(unsigned long) + 2) + 1) > oidBufLen)
        {
            printf("Asn1Id2LdapOid: output buffer len %d is too small.\n",
                    oidBufLen);
            index = 0;
            err = ERR_INSUFFICIENT_BUFFER;
            goto _Asn1Id2LdapOidExit;
        }

        /* High bit means this is not the last part of this element. */
        while ((cur[i] & 0x80) == 0x80)
        {
            /* Multiply the result of last time through the 
             * loop by 128, and then add the low bits to it.
             */
            value = (0x80L * value) + (cur[i++] & (0x7F));
        }

        /* This is the last part of this element,
         * so multiply and add one final time.
         */
        value = (0x80L * value) + cur[i++];

        index += sprintf(&(oidBuf[index]), ".%lu", value);
    }

_Asn1Id2LdapOidExit:
    oidBuf[index] = '\0';
    return err;
}



