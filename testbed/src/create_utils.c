 /* ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.  All Rights Reserved.
 *
 * Contributor(s):  Karen Sirois
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "cryptlib.h"
#include "certificate.h"
#include <roa.h>
#include <keyfile.h>
#include <casn.h>
#include <asn.h>
#include <time.h>
#include "create_object.h"
#include "obj_err.h"
#include "roa.h"

#define IPv4 4
#define IPv6 6
#define ASNUM 8

extern char *signCMS(struct ROA *roap, char *keyfile, int bad); 
int  txt2loc(int typ, char *buf, struct iprange *iprangep);
static void make_IPAddrOrRange(struct IPAddressOrRangeA *ipAddrOrRangep,
			       struct iprange *tiprangep);

/**
 * Writes an EEcert into a ROA or Manifest
 *
 * author: Brenton Kohler
 */
int write_EEcert(void* my_var, void* value)
{
  struct Certificate my_cert;
  struct ROA* roa = my_var;
  Certificate(&my_cert, (ushort)0);

  //read the EE certificate from file
  if( !(get_casn_file(&my_cert.self, (char*)value,0) < 0) ) 
    {
      struct SignedData *sgdp = &roa->content.signedData;
      //Clear the old one
      clear_casn(&sgdp->certificates.self);
      
      struct Certificate *sigcertp = (struct Certificate *)inject_casn(&sgdp->certificates.self, 0);
      
      //copy the new one in
      if(sigcertp != NULL)
	copy_casn(&sigcertp->self, &my_cert.self);
      else
	{
	  warn(1,"ERROR injecting EE cert");
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
int write_EEkey(void* my_var, void* value)
{
  struct Certificate my_cert;
  struct ROA* roa = my_var;
  Certificate(&my_cert, (ushort)0);

  //read the EE certificate from file
  if( !(get_casn_file(&my_cert.self, (char*)value,0) < 0) ) 
    {
      struct SignedData *sgdp = &roa->content.signedData;
      //Clear the old one
      clear_casn(&sgdp->certificates.self);
      
      struct Certificate *sigcertp = (struct Certificate *)inject_casn(&sgdp->certificates.self, 0);
      
      //copy the new one in
      if(sigcertp != NULL)
	copy_casn(&sigcertp->self, &my_cert.self);
      else
	{
	  warn(1,"ERROR injecting EE cert");
	  return 1;
	}
    }
  else
    return 1;
  return SUCCESS;
}

// read ascii valus from from_val and convert into hex in to_val
// not to_val buffer is allocated by the caller
int read_hex_val(char *from_val, int len, unsigned char *to_val)
{
  int i = 0, j;
  unsigned int byte;


  // if it doesn't start with '0x' then return without converting
  if (strncmp(from_val, "0x", 2) == 0)
    i = 2;
  
  j = 0;
  for (; i < len; i+=2)
    {
      sscanf(&from_val[i], "%2x",&byte);
      memcpy(&to_val[j],(unsigned char *) &byte, 1);
      j++;
    }

  return j;
}

char *stripQuotes(char *str)	  
{
  char *tmpval = str;
  char *end;

  if (strlen(tmpval) > 0)
    { 
      if (strncmp(tmpval, "\"", 1) == 0)
	tmpval++;
      end = tmpval+strlen(tmpval)-1;
      if (strncmp((char *)end,"\"", 1) == 0)
	*end = '\0';
      return tmpval;
    }

  return NULL;
}

/*
 * Alloc memory, copy string and strip white space.
 * return new string. 
 */
char *stripws(char *str)
{
  
  char *end;
  char *value;
  int len;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return NULL;

  // Copy string and trim trailing space
  len = strlen(str);
  if ((value = calloc(len+1, sizeof(char))) == NULL)
    return NULL;

  memcpy(value,str, len);
  end = value + strlen(value) - 1;
  while(end > value && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return value;
}

/*
 * Find the offset for this field in the table (the table is passed in)
 * t_field - table field
 */
int fieldInTable(char *field, int field_len, struct object_field *tbl)
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
	  return i; // same length and match, done
      t_field = tbl[++i].name;
    }
  // not found
  return -1;
}

// return 0 for success and -1 for failure
// outputs value from table and type (TEXT,OCTETSTRING...)
int get_table_value(char *name, struct object_field *table, char **value, int *type)
{
  int offset;

  offset = fieldInTable(name, strlen(name),table);
  if ( offset < 0 )
    return -1;

  *value = table[offset].value;
  *type =  table[offset].type;
  fprintf(stdout,"Value and type for %s is %s, %d\n", name, *value, *type);
  return SUCCESS;
}

// return 0 for success - valid table and -1 for failure, some missing fields
// If any 'required' field is not filled in then add missing field to the
// list of errors and keep looking
int validate_table(struct object_field *table, char *errstr, int len)
{
  int i = 0;
  int err = 0;
  char *name;
  
  // zero out the error string
  memset(errstr,0, len);
  name = table[i].name;
  while (name != NULL)
    {
      if ((table[i].value == NULL) && 
	  (table[i].required == REQUIRED))
	{
	  if (err != 0) // not first error, add comma
	    strcat(errstr,", ");
	  strcat(errstr,name);
	  err = 1;
	}
      name = table[++i].name;
    }
  if (err)
    return -1;

  return SUCCESS;
}

/* utility to print object field table */
void print_table(struct object_field *table)
{
  int i=0;

  fprintf(stdout, "Current object table is:\n");
  while (table[i].name != NULL)
    {
      fprintf(stdout, "  %s = %s\n", table[i].name,table[i].value);
      i++;
    }
}

void removeExtension(struct Extensions *extsp, char *oid)
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


struct Extension *findExtension(struct Extensions *extsp, char *oid)
  {
  struct Extension *extp;
  if (!num_items(&extsp->self)) 
    return (struct Extension *)0;

  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, oid);
    extp = (struct Extension *)next_of(&extp->self));
  return extp;
  }

struct Extension *makeExtension(struct Extensions *extsp, char *idp)
  {
    struct Extension *extp;
    if (!(extp = findExtension(extsp, idp)))
      {
	extp = (struct Extension *)inject_casn(&extsp->self,
					       num_items(&extsp->self));
      }
    else clear_casn(&extp->self);
    
    write_objid(&extp->extnID, idp);
    return extp;
  }

static int cvtv4(uchar fill, char *ip, uchar *buf)
  {
  uchar *uc, *ue = &buf[4];
  char *c;
  int fld;
  for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') || 
    *c == '.' || *c == '/');
    c++);
  if (*c > ' ') return -2;
  memset(buf, fill, 4);
  for (c = ip, uc = buf; *c && *c != '/'; )
    {
    if (*c == '.') c++;
    sscanf(c, "%d", &fld);
    if (uc >= ue || fld > 255) return -1;
    *uc++ = (uchar)fld;
    while (*c > ' ' && *c != '.' && *c != '/') c++;
    }
  if (*c) 
    {
    uchar mask;
    c++;
    sscanf(c, "%d", &fld); // fld has total number of bits
    if (fld >= 32) return (fld > 32)? -1: 0;
    if (uc < &buf[fld >> 3]) return -1;
    uc = &buf[(fld >> 3)];  // points to char having bit beyond last
    fld %= 8;   // number of used bits in last byte
    fld = 8 - fld;   // number of unused 
    mask = ~(0xFF << fld);  // mask for last byte
    if (fill) 
      {
      mask = ~mask;
      if ((mask & *uc)) return -1;
      *uc |= (~mask);
      }
    else 
      {
      if ((mask & *uc)) return -1;
      *uc &= mask;
      }
    }
  return 0;
  }
    
static int cvtv6(uchar fill, char *ip, uchar *buf)
{
  uchar *up, *ue;
  char *c;
  int fld, elided;
  for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') || 
      ((*c | 0x20) >= 'a' && (*c | 0x20) <= 'f') || *c == ':' || *c == '/');
       c++);
  if (*c > ' ') return -2;
  for (up = buf, ue = &buf[16]; up < ue; *up++ = fill);
  for (c = ip, elided = 8; *c && *c != '/'; c++)
    {
    if (*c == ':') elided--;
    } 
  for (c = ip, up = buf; *c > ' ' && *c != '/';)
    {
    if (*c == ':') c++;
    sscanf(c, "%x", &fld);
    if (up >= ue || fld > 0xFFFF) return -1;
    *up++ = (uchar)((fld >> 8) &0xFF);
    *up++ = (uchar)(fld & 0xFF);
    while(*c && *c != ':' && *c != '/') c++;
    if (*c == ':' && c[1] == ':')
      {
      while(elided) 
        {
	  if (c[2] == '/')
	    {
	      *up++ = fill;
	      *up++ = fill;
	    }
	  else
	    {
	      *up++ = 0;
	      *up++ = 0;
	    }
	  elided--;
        }
      //      c++;
      c+=2;
      }
    }
  if (*c) 
    {
    ushort mask;
    c++;
    sscanf(c, "%d", &fld); // fld has total number of bits
    if (fld >= 128) return (fld > 128)? -1: 0;
    if (up < &buf[fld >> 3]) return -1;
    up = &buf[(fld >> 3)];
    fld %= 16;   // number of used bits in last ushort
    fld = 16 - fld;  // number of unused bits
    mask = (0xFFFF << fld);  // mask for last ushort
    if (fill) 
      {
      mask = ~mask;
          // if up is at the high byte in a short
      if (!((up - buf) & 1)) *up++ |= ((mask >> 8) & 0xFF);
      *up |= (mask & 0xFF);
      }
    else 
      {
      *up++ &= ((mask >> 8) & 0xFF);
      *up   &= (mask & 0xFF);
      }
    }
  return 0;
}

int write_ASNums(struct ASNum *asnump, char *buf, int num)
{
  char *a;
  struct ASNumberOrRangeA  *asNumorRangep;

  asNumorRangep = (struct ASNumberOrRangeA *)
    inject_casn(&asnump->asnum.asNumbersOrRanges.self, num);

  for (a = buf; *a && (*a == '-' || (*a >= '0' && *a <= '9')); a++);
  if (*a)
    return -1;

  for (a = buf; *a && *a != '-'; a++);
  int val;
  if (!*a)
    {
      if (sscanf(buf, "%d", &val) != 1 ||
	  write_casn_num(&asNumorRangep->num, val) <= 0) 
	return(-1);
    }
  else
    {
      if (sscanf(buf, "%d", &val) != 1 ||
	  write_casn_num(&asNumorRangep->range.min, val) <= 0 ||
	  sscanf(++a, "%d", &val) != 1 ||
	  write_casn_num(&asNumorRangep->range.max, val) <= 0)
	return(-1);
    }
  return SUCCESS;
}


int write_family(struct IPAddressFamilyA *famp, char *buf, int num)
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

  ipAorRp = (struct IPAddressOrRangeA *) inject_casn(&ipAddrOrRangesp->self, num);
  make_IPAddrOrRange(ipAorRp, &iprangep);
  return SUCCESS;
}

int  txt2loc(int typ, char *buf, struct iprange *iprangep)
{
  int ansr;
  char *c, *d = strchr(buf, (int)'-');
  ulong ASnum;
  iprangep->typ = typ;
  memset(iprangep->lolim, 0, 16);
  memset(iprangep->hilim, 0xFF, 16);
  if (d && *d) d++;
  else d = (char *)0;
  if (typ == ASNUM)
    {
    for (c = buf; *c == '-' || (*c >= '0' && *c <= '9'); c++);
    if (*c > ' ') return -2; 
    sscanf(buf, "%ld", &ASnum);
    uchar *top;
    for (top = &iprangep->lolim[3]; top >= iprangep->lolim; top--)
      {
      *top = (uchar)(ASnum & 0xFF);
      ASnum >>= 8;
      }
    if (!d) memcpy(iprangep->hilim, iprangep->lolim, 4);
    else 
      {
      sscanf(d, "%ld", &ASnum);
      for (top = &iprangep->hilim[3]; top >= iprangep->hilim; top--)
        {
        *top = (uchar)(ASnum & 0xFF);
        ASnum >>= 8;
        }
      }
    }
  else if (typ == IPv4) 
    {
      char *min = NULL;
      if (d) // copy low if it is a range
	min = copy_string(buf, (char *)d - buf -1);
      if ((ansr = cvtv4((uchar)0, (min)?min: buf, iprangep->lolim)) < 0 ||
	  (ansr = cvtv4((uchar)0xff, (d)? d: buf, iprangep->hilim)) < 0) 
	{
	  if (min != NULL) free(min);
	  return ansr;
	}
      if (min != NULL) free(min);
    }
  else if (typ == IPv6)
    {
      char *min = NULL;
      if (d) // copy low if it is a range
	min = copy_string(buf, (char *)d - buf -1);
      if ((ansr = cvtv6((uchar)0,  (min)?min:buf, iprangep->lolim)) < 0 ||
	  (ansr = cvtv6((uchar)0xff, (d)? d: buf, iprangep->hilim)) < 0) 
	{
	  if (min != NULL) free(min);
	  return ansr;
	}
      if (min != NULL) free(min);
    }
  else return -1;
  return 0;
}

// copy the string by allocating memory and copying the string into the
// newly allocated memory
char *copy_string(char *str, int num)
{
  char *buf;

  if ((buf = calloc(num + 1, sizeof(char))) == NULL)
    return NULL;

  memcpy(buf,str, num);
  return buf;
}


void make_IPAddrOrRange(struct IPAddressOrRangeA *ipAddrOrRangep,
			struct iprange *tiprangep)
{
/*
Procedure:
1. Running from left to right, find where the low and high of tiprangep differ
   Count the number of bits where they match
2. IF beyond that point lolim is all zeroes and hilim all ones, write a prefix
3. ELSE make a range thus
    Find the last non-zero byte in the minimum
    Write those bytes to the min field
    Fill in the number of unused bits in the min field
    Find the last non-FF byte in the max field
    Write those bytes in the max field
    Fill in the number of unused bits in the max field
*/
  int lth = tiprangep->typ == IPv4? 4: 16;
  uchar *hucp, *lucp, *eucp = &tiprangep->lolim[lth];
  uchar mask;
  uchar omask;
  int numbits = 0;
                                                   // step 1
  for (lucp = tiprangep->lolim, hucp = tiprangep->hilim;
    lucp < eucp && *lucp == *hucp;
    lucp++,  hucp++, numbits += 8);
  if (lucp < eucp)
    {
    for (mask = 0x80; mask && (mask & *lucp) == (mask & *hucp);
      mask >>= 1, numbits++);
    }
       // at first difference. test remains of byte
  while(mask && !(mask & *lucp) && (mask & *hucp)) mask >>= 1;
  if (!mask) // now test remainder of bytes
    {
    for (lucp++, hucp++; lucp < eucp && !*lucp && *hucp == 0xff;
      lucp++, hucp++);
    }
  uchar bitstring[18];
  int strlth;
  clear_casn(&ipAddrOrRangep->self);
  if (!mask && lucp >= eucp)                // step 2
    {
    strlth = (numbits + 7) >> 3;
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    bitstring[0] = (8 - (numbits & 7)) & 7;
    write_casn(&ipAddrOrRangep->addressPrefix, bitstring, strlth + 1);
    }
                                                   // step 3
  else
    {
      // low end
      if (tiprangep->typ == IPv4) 
	lucp = &tiprangep->lolim[3];
      else 
	lucp = &tiprangep->lolim[15];
      while (lucp > (uchar *)&tiprangep->lolim && !*lucp) lucp--;
      strlth = (lucp - tiprangep->lolim) + 1;
      memcpy(&bitstring[1], tiprangep->lolim, strlth);
      for (bitstring[0] = 0, mask = *lucp; !(mask & 1);
	   mask >>= 1, bitstring[0]++);
      write_casn(&ipAddrOrRangep->addressRange.min, bitstring, strlth + 1);
      
      // high end
      if (tiprangep->typ == IPv4) 
	lucp = &tiprangep->hilim[3];
      else 
	lucp = &tiprangep->hilim[15];
      while (lucp > (uchar *)&tiprangep->hilim && *lucp == 0xFF) lucp--;
      strlth = (lucp - tiprangep->hilim) + 1;
      memcpy(&bitstring[1], tiprangep->hilim, strlth);
      //      mask = (*lucp >> 1);
      //      bitstring[strlth] &= ~mask;
      mask = (*lucp);
      omask = 0xFF;
      for (bitstring[0] = 0; (mask & 1); mask >>= 1,omask <<= 1, bitstring[0]++);
      bitstring[strlth] &= omask;

      write_casn(&ipAddrOrRangep->addressRange.max, bitstring, strlth + 1);
    }
}
