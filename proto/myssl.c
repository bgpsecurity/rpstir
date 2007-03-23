/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

#include "myssl.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

/*
  Convert between a time string as defined by a GENERALIZED_TIME
  and a time string that will be acceptable to the DB. The return
  value is allocated memory.

  The GENERALIZED_TIME is in the form YYMMDDHHMMSST, where each of
  the fields is as follows:
      if YY <= 36 the year is 2000+YY otherwise it is 1900+YY
      1 <= MM <= 12
      1 <= DD <= 31
      0 <= HH <= 24
      0 <= MM <= 60
      0 <= SS <= 60
      T, is present and == Z indicates GMT
*/

char *ASNTimeToDBTime(char *bef, int *stap)
{
  int   year;
  int   mon;
  int   day;
  int   hour;
  int   min;
  int   sec;
  int   cnt;
  char  tz = 0;
  char *out;

  if ( stap == NULL )
    return(NULL);
  *stap = 0;
  if ( bef == NULL || bef[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  cnt = sscanf(bef, "%2d%2d%2d%2d%2d%2d%c", &year, &mon, &day,
	       &hour, &min, &sec, &tz);
  if ( cnt != 7 )
    {
      *stap = ERR_SCM_INVALDT;
      return(NULL);
    }
  if ( tz != 'Z' || mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 ||
       hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 61 )
    /* 61 because of leap seconds */
    {
      *stap = ERR_SCM_INVALDT;
      return(NULL);
    }
  if ( year > 36 )
    year += 1900;
  else
    year += 2000;
  out = (char *)calloc(24, sizeof(char));
  if ( out == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  (void)sprintf(out, "%4d-%02d-%02d %02d:%02d:%02d",
		year, mon, day, hour, min, sec);
  return(out);
}

void freecf(cert_fields *cf)
{
  int i;

  if ( cf == NULL )
    return;
  for(i=0;i<CF_NFIELDS;i++)
    {
      if ( cf->fields[i] != NULL )
	{
	  free((void *)(cf->fields[i]));
	  cf->fields[i] = 0;
	}
    }
  free((void *)cf);
}

static char *strappend(char *instr, char *nstr)
{
  char *outstr;
  int   leen;

  if ( nstr == NULL || nstr[0] == 0 )
    return(instr);
  if ( instr == NULL )
    return(strdup(nstr));
  leen = strlen(instr) + strlen(nstr) + 24;
  outstr = (char *)calloc(leen, sizeof(char));
  if ( outstr == NULL )
    return(instr);
  (void)sprintf(outstr, "%s;%s", instr, nstr);
  free((void *)instr);
  return(outstr);
}

static char *addgn(char *ptr, GENERAL_NAME *gen)
{
  char  oline[1024];
  char *optr = ptr;

  if ( gen == NULL )
    return(ptr);
  switch ( gen->type )
    {
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
      optr = strappend(ptr, (char *)(gen->d.ia5->data));
      break;
    case GEN_DIRNAME:
      oline[0] = 0;
      X509_NAME_oneline(gen->d.dirn, oline, 1024);
      if ( oline[0] != 0 )
	optr = strappend(ptr, oline);
    }
  return(optr);
}

static char *cf_get_subject(X509 *x, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  ptr = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOSUBJECT;
      return(NULL);
    }
  dptr = strdup(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_issuer(X509 *x, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  ptr = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOISSUER;
      return(NULL);
    }
  dptr = strdup(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_sn(X509 *x, int *stap, int *x509stap)
{
  ASN1_INTEGER *a1;
  BIGNUM *bn;
  char   *ptr;
  char   *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  a1 = X509_get_serialNumber(x);
  if ( a1 == NULL )
    {
      *stap = ERR_SCM_NOSN;
      return(NULL);
    }
  bn = ASN1_INTEGER_to_BN(a1, NULL);
  if ( bn == NULL )
    {
      *stap = ERR_SCM_BIGNUMERR;
      return(NULL);
    }
  ptr = BN_bn2dec(bn);
  if ( ptr == NULL )
    {
      BN_free(bn);
      *stap = ERR_SCM_BIGNUMERR;
      return(NULL);
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  BN_free(bn);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_from(X509 *x, int *stap, int *x509stap)
{
  ASN1_GENERALIZEDTIME *nb4;
  unsigned char *bef = NULL;
  char *dptr;
  int   asn1sta;

  nb4 = X509_get_notBefore(x);
  if ( nb4 == NULL )
    {
      *stap = ERR_SCM_NONB4;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *)nb4);
  if ( asn1sta < 0 )		/* error */
    {
      *x509stap = asn1sta;
      *stap = ERR_SCM_X509;
      return(NULL);
    }
  if ( bef == NULL || asn1sta == 0 ) /* null string */
    {
      *stap = ERR_SCM_NONB4;
      return(NULL);
    }
  dptr = ASNTimeToDBTime((char *)bef, stap);
  OPENSSL_free(bef);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_to(X509 *x, int *stap, int *x509stap)
{
  ASN1_GENERALIZEDTIME *naf;
  unsigned char *aft = NULL;
  char *dptr;
  int   asn1sta;

  naf = X509_get_notAfter(x);
  if ( naf == NULL )
    {
      *stap = ERR_SCM_NONAF;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *)naf);
  if ( asn1sta < 0 )		/* error */
    {
      *x509stap = asn1sta;
      *stap = ERR_SCM_X509;
      return(NULL);
    }
  if ( aft == NULL || asn1sta == 0 ) /* null string */
    {
      *stap = ERR_SCM_NONAF;
      return(NULL);
    }
  dptr = ASNTimeToDBTime((char *)aft, stap);
  OPENSSL_free(aft);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static void cf_get_ski(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  if ( meth->i2s == NULL )
    {
      *stap = ERR_SCM_BADEXT;
      return;
    }
  ptr = meth->i2s(meth, exts);
  if ( ptr == NULL || ptr[0] == 0 )
    {
      *stap = ERR_SCM_BADEXT;
      return;
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return;
    }
  cf->fields[CF_FIELD_SKI] = dptr;
}

static void cf_get_aki(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  AUTHORITY_KEYID *aki;
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  aki = (AUTHORITY_KEYID *)exts;
  if ( aki->keyid == NULL )
    {
      *stap = ERR_SCM_XPROFILE;
      return;
    }
  ptr = hex_to_string(aki->keyid->data, aki->keyid->length);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_INVALEXT;
      return;
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return;
    }
  cf->fields[CF_FIELD_AKI] = dptr;
}

static void cf_get_sia(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  AUTHORITY_INFO_ACCESS *aia;
  ACCESS_DESCRIPTION    *desc;
  GENERAL_NAME *gen;
  char *ptr = NULL;
  int   i;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  aia = (AUTHORITY_INFO_ACCESS *)exts;
  for(i=0;i<sk_ACCESS_DESCRIPTION_num(aia);i++)
    {
      desc = sk_ACCESS_DESCRIPTION_value(aia, i);
      if ( desc != NULL )
	{
	  gen = desc->location;
	  if ( gen != NULL )
	    ptr = addgn(ptr, gen);
	}
    }
  cf->fields[CF_FIELD_SIA] = ptr;
}

static void cf_get_aia(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  AUTHORITY_INFO_ACCESS *aia;
  ACCESS_DESCRIPTION    *desc;
  GENERAL_NAME *gen;
  char *ptr = NULL;
  int   i;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  aia = (AUTHORITY_INFO_ACCESS *)exts;
  for(i=0;i<sk_ACCESS_DESCRIPTION_num(aia);i++)
    {
      desc = sk_ACCESS_DESCRIPTION_value(aia, i);
      if ( desc != NULL )
	{
	  gen = desc->location;
	  if ( gen != NULL )
	    ptr = addgn(ptr, gen);
	}
    }
  cf->fields[CF_FIELD_AIA] = ptr;
}

static void cf_get_crldp(X509V3_EXT_METHOD *meth, void *exts,
			 cert_fields *cf, int *stap, int *x509stap)
{
  STACK_OF(DIST_POINT) *crld;
  GENERAL_NAMES *gen;
  GENERAL_NAME  *gen1;
  DIST_POINT    *point;
  char *ptr = NULL;
  int   j;
  int   k;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  crld = (STACK_OF(DIST_POINT) *)exts;
  for(j=0;j<sk_DIST_POINT_num(crld);j++)
    {
      point = sk_DIST_POINT_value(crld, j);
      if ( point != NULL && point->distpoint != NULL &&
	   point->distpoint->type == 0 )
	{
	  gen = point->distpoint->name.fullname;
	  if ( gen != NULL )
	    {
	      for(k=0;k<sk_GENERAL_NAME_num(gen);k++)
		{
		  gen1 = sk_GENERAL_NAME_value(gen, k);
		  if ( gen1 != NULL )
		    ptr = addgn(ptr, gen1);
		}
	    }
	}
    }
  cf->fields[CF_FIELD_CRLDP] = ptr;
}

static void cf_get_flags(X509V3_EXT_METHOD *meth, void *exts,
			 cert_fields *cf, int *stap, int *x509stap)
{
  BASIC_CONSTRAINTS *bk;
  int isca;

  UNREFERENCED_PARAMETER(meth);
  if ( stap == NULL )
    return;
  if ( exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  bk = (BASIC_CONSTRAINTS *)exts;
  isca = bk->ca;
  if ( isca != 0 )
    cf->flags |= SCM_FLAG_CA;
}

static cfx_validator xvalidators[] = 
  {
    { cf_get_ski,     CF_FIELD_SKI,     NID_subject_key_identifier,   1 } ,
    { cf_get_aki,     CF_FIELD_AKI,     NID_authority_key_identifier, 1 } ,
    { cf_get_sia,     CF_FIELD_SIA,     NID_sinfo_access,             0 } ,
    { cf_get_aia,     CF_FIELD_AIA,     NID_info_access,              0 } ,
    { cf_get_crldp,   CF_FIELD_CRLDP,   NID_crl_distribution_points,  0 } ,
    { cf_get_flags,   0,                NID_basic_constraints,        0 }
  } ;

/*
  Given an X509V3 extension tag, this function returns the corresponding
  extension validator.
*/

static cfx_validator *cfx_find(int tag)
{
  unsigned int i;

  for(i=0;i<sizeof(xvalidators)/sizeof(cfx_validator);i++)
    {
      if ( xvalidators[i].tag == tag )
	return(&xvalidators[i]);
    }
  return(NULL);
}

static cf_validator validators[] = 
{
  { NULL,           0,                0 } , /* filename handled already */
  { cf_get_subject, CF_FIELD_SUBJECT, 1 } ,
  { cf_get_issuer,  CF_FIELD_ISSUER,  1 } ,
  { cf_get_sn,      CF_FIELD_SN,      1 } ,
  { cf_get_from,    CF_FIELD_FROM,    1 } ,
  { cf_get_to,      CF_FIELD_TO,      1 } ,
  { NULL,           0,                0 }   /* terminator */
} ;

/*
  This function opens a certificate from a file and extracts all the fields
  from it.  It does not touch the DB at all, it just manipulates the certificate.

  On success this function returns a pointer to allocated memory containing
  all the indicated fields (except the three integer fields) and sets stap to 0,
  and x509stap to 1.

  Note carefully that this function does NOT set all the fields in the cf.
  In particular, it is the responsibility of the caller to set the dirid
  and myid fields.  These two fields require DB access and are therefore
  not part of this function.

  On failure this function returns NULL and sets stap to a non-negative error
  code. If an X509 error occurred, x509stap is set to that error.
*/

cert_fields *cert2fields(char *fname, char *fullname, int typ, X509 **xp,
			 int *stap, int *x509stap)
{
  const unsigned char *udat;
  cfx_validator       *cfx;
  X509V3_EXT_METHOD   *meth;
  X509_EXTENSION      *ex;
  X509_CINF   *ci;
  cert_fields *cf;
  unsigned int ui;
  BIO  *bcert;
  X509 *x;
  void *exts;
  char *res;
  int   x509sta;
  int   excnt;
  int   i;

  if ( stap == NULL || x509stap == NULL )
    return(NULL);
  *x509stap = 1;
  if ( fname == NULL || fname[0] == 0 || fullname == NULL || fullname[0] == 0 ||
       xp == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  *xp = NULL;
  cf = (cert_fields *)calloc(1, sizeof(cert_fields));
  if ( cf == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  cf->fields[CF_FIELD_FILENAME] = strdup(fname);
  if ( cf->fields[CF_FIELD_FILENAME] == NULL )
    {
      freecf(cf);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
// open the file
  bcert = BIO_new(BIO_s_file());
  if ( bcert == NULL )
    {
      freecf(cf);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  x509sta = BIO_read_filename(bcert, fullname);
  if ( x509sta <= 0 )
    {
      BIO_free_all(bcert);
      freecf(cf);
      *stap = ERR_SCM_X509;
      *x509stap = x509sta;
      return(NULL);
    }
// read the cert based on the input type
  if ( typ < OT_PEM_OFFSET )
    x = d2i_X509_bio(bcert, NULL);
  else
    x = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
  if ( x == NULL )
    {
      BIO_free_all(bcert);
      freecf(cf);
      *stap = ERR_SCM_BADCERT;
      return(NULL);
    }
// get all the non-extension fields; if a field cannot be gotten and its
// critical, that is a fatal error
  for(i=1;i<CF_NFIELDS;i++)
    {
      if ( validators[i].get_func == NULL )
	break;
      res = (*validators[i].get_func)(x, stap, x509stap);
      if ( res == NULL && validators[i].critical > 0 )
	{
	  X509_free(x);
	  BIO_free_all(bcert);
	  freecf(cf);
	  if ( *stap == 0 )
	    *stap = ERR_SCM_X509;
	  return(NULL);
	}
      cf->fields[i] = res;
    }
// get the extension fields
  excnt = X509_get_ext_count(x);
  ci = x->cert_info;
  for(i=0;i<excnt;i++)
    {
      ex = sk_X509_EXTENSION_value(ci->extensions, i);
      if ( ex == NULL )
	continue;
      meth = X509V3_EXT_get(ex);
      if ( meth == NULL )
	continue;
      udat = ex->value->data;
      if ( meth->it )
	exts = ASN1_item_d2i(NULL, &udat, ex->value->length,
			     ASN1_ITEM_ptr(meth->it));
      else
	exts = meth->d2i(NULL, &udat, ex->value->length);
      if ( exts == NULL )
	continue;
      cfx = cfx_find(meth->ext_nid);
      if ( cfx == NULL || cfx->get_func == NULL )
	continue;
      *stap = 0;
      *x509stap = 0;
      (*cfx->get_func)(meth, exts, cf, stap, x509stap);
      if ( *stap != 0 && cfx->critical != 0 )
	break;
      if ( meth->it )
	ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
      else
	meth->ext_free(exts);
    }
// check that all critical extension fields are present
  for(ui=0;ui<sizeof(xvalidators)/sizeof(cfx_validator);ui++)
    {
      if ( xvalidators[ui].critical != 0 &&
	   cf->fields[xvalidators[ui].fieldno] == NULL )
	{
	  *stap = ERR_SCM_MISSEXT;
	  break;
	}
    }
  BIO_free_all(bcert);
  if ( *stap != 0 )
    {
      freecf(cf);
      X509_free(x);
      cf = NULL;
    }
  *xp = x;
  return(cf);
}
