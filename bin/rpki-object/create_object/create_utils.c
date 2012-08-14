
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "util/cryptlib_compat.h"
#include "rpki-object/certificate.h"
#include "rpki-object/cms/cms.h"
#include <rpki-asn1/roa.h>
#include <rpki-asn1/keyfile.h>
#include <casn/casn.h>
#include <casn/asn.h>
#include <time.h>
#include "create_object.h"
#include "obj_err.h"
#include <util/inet.h>
#include <rpki/rpwork.h>

/**
 * Writes an EEcert into a ROA or Manifest
 *
 * author: Brenton Kohler
 */
int write_EEcert(
    void *my_var,
    void *value)
{
    struct Certificate my_cert;
    struct ROA *roa = my_var;
    Certificate(&my_cert, (ushort) 0);

    // read the EE certificate from file
    if (!(get_casn_file(&my_cert.self, (char *)value, 0) < 0))
    {
        struct SignedData *sgdp = &roa->content.signedData;
        // Clear the old one
        eject_all_casn(&sgdp->certificates.self);

        struct Certificate *sigcertp =
            (struct Certificate *)inject_casn(&sgdp->certificates.self, 0);

        // copy the new one in
        if (sigcertp != NULL)
            copy_casn(&sigcertp->self, &my_cert.self);
        else
        {
            warn(1, "ERROR injecting EE cert");
            return 1;
        }
    }
    else
        return 1;
    return SUCCESS;
}

/**
 * Writes an EEkey into a ROA or Manifest
 *
 * author: Brenton Kohler
 */
int write_EEkey(
    void *my_var,
    void *value)
{
    // struct Certificate my_cert;
    struct ROA *roa = my_var;
    // Certificate(&my_cert, (ushort)0);
    char *c;

    if ((c = signCMS(roa, (char *)value, 0)))
    {
        warn(1, "Error signing with the EE key file");
        return 1;
    }

    // read the EE certificate from file
    /*
     * if( !(get_casn_file(&my_cert.self, (char*)value,0) < 0) ) 
     */
    /*
     * { 
     */
    /*
     * struct SignedData *sgdp = &roa->content.signedData; 
     */
    /*
     * //Clear the old one 
     */
    /*
     * clear_casn(&sgdp->certificates.self); 
     */

    /*
     * struct Certificate *sigcertp = (struct Certificate
     * *)inject_casn(&sgdp->certificates.self, 0); 
     */

    /*
     * //copy the new one in 
     */
    /*
     * if(sigcertp != NULL) 
     */
    /*
     * copy_casn(&sigcertp->self, &my_cert.self); 
     */
    /*
     * else 
     */
    /*
     * { 
     */
    /*
     * warn(1,"ERROR injecting EE cert"); 
     */
    /*
     * return 1; 
     */
    /*
     * } 
     */
    /*
     * } 
     */
    /*
     * else 
     */
    /*
     * return 1; 
     */
    return SUCCESS;
}

// read ascii valus from from_val and convert into hex in to_val
// not to_val buffer is allocated by the caller
int read_hex_val(
    char *from_val,
    int len,
    unsigned char *to_val)
{
    int i = 0,
        j;
    unsigned int byte;


    // if it doesn't start with '0x' then return without converting
    if (strncmp(from_val, "0x", 2) == 0)
        i = 2;

    j = 0;
    for (; i < len; i += 2)
    {
        sscanf(&from_val[i], "%2x", &byte);
        memcpy(&to_val[j], (unsigned char *)&byte, 1);
        j++;
    }

    return j;
}

char *stripQuotes(
    char *str)
{
    char *tmpval = str;
    char *end;

    if (!str)
        return NULL;

    if (strlen(tmpval) > 0)
    {
        if (strncmp(tmpval, "\"", 1) == 0)
            tmpval++;
        end = tmpval + strlen(tmpval) - 1;
        if (strncmp((char *)end, "\"", 1) == 0)
            *end = '\0';
        return tmpval;
    }

    return NULL;
}

/*
 * Alloc memory, copy string and strip white space.
 * return new string. 
 */
char *stripws(
    char *str)
{

    char *end;
    char *value;
    int len;

    // Trim leading space
    while (isspace((int)(unsigned char)*str))
        str++;

    if (*str == 0)              // All spaces?
        return NULL;

    // Copy string and trim trailing space
    len = strlen(str);
    if ((value = calloc(len + 1, sizeof(char))) == NULL)
        return NULL;

    memcpy(value, str, len);
    end = value + strlen(value) - 1;
    while (end > value && isspace((int)(unsigned char)*end))
        end--;

    // Write new null terminator
    *(end + 1) = 0;

    return value;
}

/*
 * Find the offset for this field in the table (the table is passed in)
 * t_field - table field
 */
int fieldInTable(
    char *field,
    int field_len,
    struct object_field *tbl)
{
    int i = 0;
    char *t_field;
    int t_field_len;

    if (field == NULL)
        return -1;


    t_field = tbl[0].name;
    while (t_field != NULL)
    {
        t_field_len = strlen(t_field);
        if (t_field_len == field_len)
            if (strncasecmp(t_field, field, t_field_len) == 0)
                return i;       // same length and match, done
        t_field = tbl[++i].name;
    }
    // not found
    return -1;
}

// return 0 for success and -1 for failure
// outputs value from table and type (TEXT,OCTETSTRING...)
int get_table_value(
    char *name,
    struct object_field *table,
    char **value,
    int *type)
{
    int offset;

    offset = fieldInTable(name, strlen(name), table);
    if (offset < 0)
        return -1;

    *value = table[offset].value;
    *type = table[offset].type;
    // fprintf(stdout,"Value and type for %s is %s, %d\n", name, *value,
    // *type);
    return SUCCESS;
}

// return 0 for success - valid table and -1 for failure, some missing fields
// If any 'required' field is not filled in then add missing field to the
// list of errors and keep looking
int validate_table(
    struct object_field *table,
    char *errstr,
    int len)
{
    int i = 0;
    int err = 0;
    char *name;

    // zero out the error string
    memset(errstr, 0, len);
    name = table[i].name;
    while (name != NULL)
    {
        if ((table[i].value == NULL) && (table[i].required == REQUIRED))
        {
            if (err != 0)       // not first error, add comma
                strcat(errstr, ", ");
            strcat(errstr, name);
            err = 1;
        }
        name = table[++i].name;
    }
    if (err)
        return -1;

    return SUCCESS;
}

/*
 * utility to print object field table 
 */
void print_table(
    struct object_field *table)
{
    int i = 0;

    fprintf(stdout, "Current object table is:\n");
    while (table[i].name != NULL)
    {
        fprintf(stdout, "  %s = %s\n", table[i].name, table[i].value);
        i++;
    }
}

void removeExtension(
    struct Extensions *extsp,
    char *oid)
{
    struct Extension *extp;
    int i = 0;

    if (!num_items(&extsp->self))
        return;

    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oid);
         extp = (struct Extension *)next_of(&extp->self), i++);

    // found the extension
    if (extp != NULL)
        eject_casn(&extsp->self, i);

    return;
}

int write_ASNums(
    struct ASNum *asnump,
    char *buf,
    int num)
{
    char *a;
    struct ASNumberOrRangeA *asNumorRangep;

    asNumorRangep =
        (struct ASNumberOrRangeA *)inject_casn(&asnump->asnum.
                                               asNumbersOrRanges.self, num);

    for (a = buf; *a && (*a == '-' || (*a >= '0' && *a <= '9')); a++);
    if (*a)
        return -1;

    for (a = buf; *a && *a != '-'; a++);
    int val;
    if (!*a)
    {
        if (sscanf(buf, "%d", &val) != 1 ||
            write_casn_num(&asNumorRangep->num, val) <= 0)
            return (-1);
    }
    else
    {
        if (sscanf(buf, "%d", &val) != 1 ||
            write_casn_num(&asNumorRangep->range.min, val) <= 0 ||
            sscanf(++a, "%d", &val) != 1 ||
            write_casn_num(&asNumorRangep->range.max, val) <= 0)
            return (-1);
    }
    return SUCCESS;
}


int write_family(
    struct IPAddressFamilyA *famp,
    char *buf,
    int num)
{
    uchar family[2];
    struct IPAddressOrRangeA *ipAorRp;
    struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp = NULL;
    struct iprange iprangep;

    read_casn(&famp->addressFamily, family);
    write_casn(&famp->addressFamily, family, 2);

    ipAddrOrRangesp = &famp->ipAddressChoice.addressesOrRanges;

    if (family[1] == 1)
    {
        if (txt2loc(IPv4, buf, &iprangep) < 0)
            return -1;
    }
    else
    {
        if (txt2loc(IPv6, buf, &iprangep) < 0)
            return -1;
    }

    ipAorRp =
        (struct IPAddressOrRangeA *)inject_casn(&ipAddrOrRangesp->self, num);
    if (!make_IPAddrOrRange(ipAorRp,
                            iprangep.typ == IPv4 ? AF_INET : AF_INET6,
                            &iprangep.lolim,
                            &iprangep.hilim))
    {
        return -1;
    }

    return SUCCESS;
}

// copy the string by allocating memory and copying the string into the
// newly allocated memory
char *copy_string(
    char *str,
    int num)
{
    char *buf;

    if ((buf = calloc(num + 1, sizeof(char))) == NULL)
        return NULL;

    memcpy(buf, str, num);
    return buf;
}
