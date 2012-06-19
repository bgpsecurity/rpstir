/*
 * File: create_object.h Contents: Header file for creating testbed objects
 * Created: Author: Karen Sirois
 * 
 * Remarks:
 * 
 * ****************************************************************************
 */
#ifndef _CREATE_OBJ_H
#define _CREATE_OBJ_H


#define CERT      1
#define CRL       2
#define ROA_LOC   3
#define MANIFEST  4

// certificate field value types
#define TEXT 1
#define INTEGER 2
#define OCTETSTRING 3           // i.e. hex string (oxff0a)
#define LIST 3                  // i.e. a comma separated list

#define REQUIRED 1
#define OPTIONAL 0

#define IPv4 4
#define IPv6 6
#define ASNUM 8

typedef int (
    *my_func) (
    void *,
    void *);

struct object_field {
    char *name;
    int type;
    char *value;
    int required;
    my_func func;
};

struct iprange {
    int typ;
    uchar lolim[18],
        hilim[18];
    ulong loASnum,
        hiASnum;
    char *text;
};

struct ipranges {
    int numranges;
    struct iprange *iprangep;
};


extern int read_hex_val(
    char *from_val,
    int len,
    unsigned char *to_val);
extern struct Extension *makeExtension(
    struct Extensions *extsp,
    char *idp);
void removeExtension(
    struct Extensions *extsp,
    char *oid);
extern struct Extension *findExtension(
    struct Extensions *extsp,
    char *oid);
extern int write_family(
    struct IPAddressFamilyA *famp,
    char *buf,
    int num);
extern int write_ASNums(
    struct ASNum *asnump,
    char *val,
    int num);
extern char *stripQuotes(
    char *str);
extern char *copy_string(
    char *str,
    int num);
extern int cvtv4(
    uchar fill,
    char *ip,
    uchar * buf);
extern int cvtv6(
    uchar fill,
    char *ip,
    uchar * buf);

extern const char *templateFile;
#endif                          /* _CREATE_OBJ_H */
