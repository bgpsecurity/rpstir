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

/*
  This function converts the local time into GMT in a form recognized
  by the DB.
*/

char *LocalTimeToDBTime(int *stap)
{
  struct tm *tmp;
  time_t clck;
  char  *out;

  if ( stap == NULL )
    return(NULL);
  *stap = 0;
  out = (char *)calloc(24, sizeof(char));
  if ( out == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  (void)time(&clck);
  tmp = gmtime(&clck);
  (void)sprintf(out, "%d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
	1900+tmp->tm_year, 1+tmp->tm_mon, tmp->tm_mday,
	tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
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
  if ( cf->ipb != NULL )
    {
      free(cf->ipb);
      cf->ipb = NULL;
    }
  cf->ipblen = 0;
  free((void *)cf);
}

void freecrf(crl_fields *cf)
{
  int i;

  if ( cf == NULL )
    return;
  for(i=0;i<CRF_NFIELDS;i++)
    {
      if ( cf->fields[i] != NULL )
	{
	  free((void *)(cf->fields[i]));
	  cf->fields[i] = 0;
	}
    }
  if ( cf->snlist != NULL )
    {
      free(cf->snlist);
      cf->snlist = NULL;
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
  OPENSSL_free(ptr);
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
  ptr = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOISSUER;
      return(NULL);
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
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

/*
  This is the raw processing function that extracts the data/length of
  the IPAddressBlock in the ASN.1 of the certificate and places them into
  the corresponding cf fields.
*/

static void cf_get_ipb(X509V3_EXT_METHOD *meth, void *ex,
		       cert_fields *cf, int *stap, int *x509stap)
{
  X509_EXTENSION *exx;
  int leen;

  UNREFERENCED_PARAMETER(meth);
  UNREFERENCED_PARAMETER(x509stap);
  if ( stap == NULL )
    return;
  exx = (X509_EXTENSION *)ex;
  leen = exx->value->length;
  if ( leen <= 0 )
    {
      cf->ipblen = 0;
      cf->ipb = NULL;
      return;
    }
  cf->ipb = calloc(leen, sizeof(unsigned char));
  if ( cf->ipb == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return;
    }
  memcpy(cf->ipb, exx->value->data, leen);
  cf->ipblen = leen;
}

static cfx_validator xvalidators[] = 
  {
    { cf_get_ski,     CF_FIELD_SKI,     NID_subject_key_identifier,   1, 0 } ,
    { cf_get_aki,     CF_FIELD_AKI,     NID_authority_key_identifier, 1, 0 } ,
    { cf_get_sia,     CF_FIELD_SIA,     NID_sinfo_access,             0, 0 } ,
    { cf_get_aia,     CF_FIELD_AIA,     NID_info_access,              0, 0 } ,
    { cf_get_crldp,   CF_FIELD_CRLDP,   NID_crl_distribution_points,  0, 0 } ,
    { cf_get_ipb,     0,                NID_sbgp_ipAddrBlock,         0, 1 } ,
    { cf_get_flags,   0,                NID_basic_constraints,        0, 0 }
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
  This function can operate in two ways.  If "fname" and "fullname" are both
  given, then it opens a certificate from a file and extracts all the fields
  from it.  If "xp" points to an already available certificate, then it just
  manipulates that. This function does not touch the DB at all, it just
  manipulates the certificate.

  On success this function returns a pointer to allocated memory containing
  all the indicated fields (except the "dirid" field) and sets stap to
  0, and x509stap to 1.

  Note carefully that this function does NOT set all the fields in the cf.
  In particular, it is the responsibility of the caller to set the dirid
  field.  This field requires DB access and are therefore is not part of
  this function.

  On failure this function returns NULL and sets stap to a negative error
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
  BIO  *bcert = NULL;
  X509 *x = NULL;
  void *exts;
  char *res;
  int   freex;
  int   x509sta;
  int   excnt;
  int   need;
  int   i;

  if ( stap == NULL || x509stap == NULL )
    return(NULL);
  *x509stap = 1;
  if ( xp == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
// case 1: filenames are given
  if ( fname != NULL && fname[0] != 0 && fullname != NULL && fullname[0] != 0 )
    {
      *xp = NULL;
      freex = 1;
      cf = (cert_fields *)calloc(1, sizeof(cert_fields));
      if ( cf == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
      cf->fields[CF_FIELD_FILENAME] = strdup(fname);
      if ( cf->fields[CF_FIELD_FILENAME] == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
// open the file
      bcert = BIO_new(BIO_s_file());
      if ( bcert == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
      x509sta = BIO_read_filename(bcert, fullname);
      if ( x509sta <= 0 )
	{
	  BIO_free(bcert);
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
      BIO_free(bcert);
      if ( x == NULL )
	{
	  freecf(cf);
	  *stap = ERR_SCM_BADCERT;
	  return(NULL);
	}
    }
// case 2: x is given
  else
    {
      x = *xp;
      if ( x == NULL )
	{
	  *stap = ERR_SCM_INVALARG;
	  return(NULL);
	}
      freex = 0;
      cf = (cert_fields *)calloc(1, sizeof(cert_fields));
      if ( cf == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
    }
// get all the non-extension fields; if a field cannot be gotten and its
// needed, that is a fatal error
  for(i=1;i<CF_NFIELDS;i++)
    {
      if ( validators[i].get_func == NULL )
	break;
      res = (*validators[i].get_func)(x, stap, x509stap);
      if ( res == NULL && validators[i].need > 0 )
	{
	  if ( freex )
	    {
	      X509_free(x);
	      x = NULL;
	    }
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
      *stap = 0;
      *x509stap = 0;
      need = 0;
      cfx = cfx_find(meth->ext_nid);
      if ( cfx != NULL && cfx->get_func != NULL )
	{
	  need = cfx->need;
	  if ( cfx->raw == 0 )
	    (*cfx->get_func)(meth, exts, cf, stap, x509stap);
	  else
	    (*cfx->get_func)(meth, ex, cf, stap, x509stap);
	}
      if ( meth->it )
	ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
      else
	meth->ext_free(exts);
      if ( *stap != 0 && need > 0 )
	break;
    }
// check that all needed extension fields are present
  for(ui=0;ui<sizeof(xvalidators)/sizeof(cfx_validator);ui++)
    {
      if ( xvalidators[ui].need > 0 &&
	   cf->fields[xvalidators[ui].fieldno] == NULL )
	{
	  *stap = ERR_SCM_MISSEXT;
	  break;
	}
    }
  if ( *stap != 0 )
    {
      freecf(cf);
      cf = NULL;
      if ( freex )
	{
	  X509_free(x);
	  x = NULL;
	}
    }
  *xp = x;
  return(cf);
}

static char *crf_get_issuer(X509_CRL *x, int *stap, int *crlstap)
{
  char *ptr;
  char *dptr;

  if ( x == NULL || stap == NULL || crlstap == NULL )
    return(NULL);
  ptr = X509_NAME_oneline(X509_CRL_get_issuer(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOISSUER;
      return(NULL);
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *crf_get_last(X509_CRL *x, int *stap, int *crlstap)
{
  ASN1_GENERALIZEDTIME *nb4;
  unsigned char *bef = NULL;
  char *dptr;
  int   asn1sta;

  nb4 = X509_CRL_get_lastUpdate(x);
  if ( nb4 == NULL )
    {
      *stap = ERR_SCM_NONB4;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *)nb4);
  if ( asn1sta < 0 )		/* error */
    {
      *crlstap = asn1sta;
      *stap = ERR_SCM_CRL;
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

static char *crf_get_next(X509_CRL *x, int *stap, int *crlstap)
{
  ASN1_GENERALIZEDTIME *naf;
  unsigned char *aft = NULL;
  char *dptr;
  int   asn1sta;

  naf = X509_CRL_get_nextUpdate(x);
  if ( naf == NULL )
    {
      *stap = ERR_SCM_NONAF;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *)naf);
  if ( asn1sta < 0 )		/* error */
    {
      *crlstap = asn1sta;
      *stap = ERR_SCM_CRL;
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

static crf_validator crvalidators[] = 
{
  { NULL,            0,                0 } , /* filename handled already */
  { crf_get_issuer,  CRF_FIELD_ISSUER, 1 } ,
  { crf_get_last,    CRF_FIELD_LAST,   0 } ,
  { crf_get_next,    CRF_FIELD_NEXT,   1 } ,
  { NULL,            0,                0 }   /* terminator */
} ;

static void crf_get_crlno(X509V3_EXT_METHOD *meth, void *exts,
			  crl_fields *cf, int *stap, int *crlstap)
{
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || crlstap == NULL )
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
  cf->fields[CRF_FIELD_SN] = dptr;
}

static void crf_get_aki(X509V3_EXT_METHOD *meth, void *exts,
			crl_fields *cf, int *stap, int *crlstap)
{
  AUTHORITY_KEYID *aki;
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || crlstap == NULL )
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
  cf->fields[CRF_FIELD_AKI] = dptr;
}

static crfx_validator crxvalidators[] = 
  {
    { crf_get_crlno,  CRF_FIELD_SN,     NID_crl_number,   0 } ,
    { crf_get_aki,    CRF_FIELD_AKI,    NID_authority_key_identifier, 1 }
  } ;

/*
  Given an X509V3 extension tag, this function returns the corresponding
  extension validator.
*/

static crfx_validator *crfx_find(int tag)
{
  unsigned int i;

  for(i=0;i<sizeof(crxvalidators)/sizeof(crfx_validator);i++)
    {
      if ( crxvalidators[i].tag == tag )
	return(&crxvalidators[i]);
    }
  return(NULL);
}

/*
  This function can operate in two ways.  If "fname" and "fullname" are both
  given, then it opens a CRL from a file and extracts all the fields
  from it.  If "xp" points to an already available CRL, then it just
  manipulates that. This function does not touch the DB at all, it just
  manipulates the CRL.

  On success this function returns a pointer to allocated memory containing
  all the indicated fields (except the "dirid" field) and sets stap to
  0, and crlstap to 1.

  Note carefully that this function does NOT set all the fields in the crf.
  In particular, it is the responsibility of the caller to set the dirid
  field.  This field requires DB access and are therefore is not part of this
  function.

  On failure this function returns NULL and sets stap to a negative error
  code. If an X509 error occurred, crlstap is set to that error.
*/

crl_fields *crl2fields(char *fname, char *fullname, int typ, X509_CRL **xp,
		       int *stap, int *crlstap)
{
  const unsigned char    *udat;
  crfx_validator         *cfx;
  STACK_OF(X509_REVOKED) *rev;
  X509V3_EXT_METHOD   *meth;
  X509_EXTENSION      *ex;
  X509_REVOKED  *r;
  unsigned char *tov;
  crl_fields    *cf;
  unsigned int   ui;
  ASN1_INTEGER  *a1;
  X509_CRL *x = NULL;
  BIGNUM   *bn;
  BIO  *bcert = NULL;
  void *exts;
  char *res;
  int   freex;
  int   crlsta;
  int   excnt;
  int   snerr;
  int   need;
  int   i;

  if ( stap == NULL || crlstap == NULL )
    return(NULL);
  *crlstap = 1;
  if ( xp == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
// case 1: filenames are given
  if ( fname != NULL && fname[0] != 0 && fullname != NULL && fullname[0] != 0 )
    {
      *xp = NULL;
      freex = 1;
      cf = (crl_fields *)calloc(1, sizeof(crl_fields));
      if ( cf == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
      cf->fields[CRF_FIELD_FILENAME] = strdup(fname);
      if ( cf->fields[CRF_FIELD_FILENAME] == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
// open the file
      bcert = BIO_new(BIO_s_file());
      if ( bcert == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
      crlsta = BIO_read_filename(bcert, fullname);
      if ( crlsta <= 0 )
	{
	  BIO_free(bcert);
	  freecrf(cf);
	  *stap = ERR_SCM_CRL;
	  *crlstap = crlsta;
	  return(NULL);
	}
// read the CRL based on the input type
      if ( typ < OT_PEM_OFFSET )
	x = d2i_X509_CRL_bio(bcert, NULL);
      else
	x = PEM_read_bio_X509_CRL(bcert, NULL, NULL, NULL);
      if ( x == NULL )
	{
	  BIO_free(bcert);
	  freecrf(cf);
	  *stap = ERR_SCM_BADCRL;
	  return(NULL);
	}
    }
// case 2: x is given
  else
    {
      x = *xp;
      if ( x == NULL )
	{
	  *stap = ERR_SCM_INVALARG;
	  return(NULL);
	}
      freex = 0;
      cf = (crl_fields *)calloc(1, sizeof(crl_fields));
      if ( cf == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
    }
// get all the non-extension fields; if a field cannot be gotten and its
// needed, that is a fatal error
  for(i=1;i<CRF_NFIELDS;i++)
    {
      if ( crvalidators[i].get_func == NULL )
	break;
      res = (*crvalidators[i].get_func)(x, stap, crlstap);
      if ( res == NULL && crvalidators[i].need > 0 )
	{
	  if ( freex )
	    X509_CRL_free(x);
	  if ( bcert != NULL )
	    BIO_free(bcert);
	  freecrf(cf);
	  if ( *stap == 0 )
	    *stap = ERR_SCM_CRL;
	  return(NULL);
	}
      cf->fields[i] = res;
    }
// get flags, snlen and snlist; note that snlen is the count in BIGINTs
  cf->flags = 0;
  rev = X509_CRL_get_REVOKED(x);
  if ( rev == NULL )
    cf->snlen = 0;
  else
    cf->snlen = sk_X509_REVOKED_num(rev);
  snerr = 0;
  if ( cf->snlen > 0 )
    {
      cf->snlist = (void *)calloc(cf->snlen, sizeof(unsigned long long));
      if ( cf->snlist == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return(NULL);
	}
      tov = (unsigned char *)(cf->snlist);
      for(ui=0;ui<cf->snlen;ui++)
	{
	  r = sk_X509_REVOKED_value(rev, ui);
	  if ( r == NULL )
	    {
	      snerr = ERR_SCM_NOSN;
	      break;
	    }
	  a1 = r->serialNumber;
	  if ( a1 == NULL )
	    {
	      snerr = ERR_SCM_NOSN;
	      break;
	    }
	  bn = ASN1_INTEGER_to_BN(a1, NULL);
	  if ( bn == NULL )
	    {
	      snerr = ERR_SCM_BIGNUMERR;
	      break;
	    }
	  if ( (unsigned)(BN_num_bytes(bn)) <= sizeof(unsigned long long) )
	    {
	      BN_bn2bin(bn, tov);
	      BN_free(bn);
	      tov += sizeof(unsigned long long);
	    }
	  else
	    {
	      snerr = ERR_SCM_BIGNUMERR;
	      BN_free(bn);
	      break;
	    }
	}
    }
  if ( snerr < 0 )
    {
      if ( bcert != NULL )
	BIO_free(bcert);
      freecrf(cf);
      if ( freex )
	X509_CRL_free(x);
      *stap = snerr;
      return(NULL);
    }
// get the extension fields
  excnt = X509_CRL_get_ext_count(x);
  for(i=0;i<excnt;i++)
    {
      ex = sk_X509_EXTENSION_value(x->crl->extensions, i);
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
      *stap = 0;
      *crlstap = 0;
      need = 0;
      cfx = crfx_find(meth->ext_nid);
      if ( cfx != NULL && cfx->get_func != NULL )
	{
	  need = cfx->need;
	  (*cfx->get_func)(meth, exts, cf, stap, crlstap);
	}
      if ( meth->it )
	ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
      else
	meth->ext_free(exts);
      if ( *stap != 0 && need > 0 )
	break;
    }
// check that all needed extension fields are present
  for(ui=0;ui<sizeof(crxvalidators)/sizeof(crfx_validator);ui++)
    {
      if ( crxvalidators[ui].need > 0 &&
	   cf->fields[crxvalidators[ui].fieldno] == NULL )
	{
	  *stap = ERR_SCM_MISSEXT;
	  break;
	}
    }
  if ( bcert != NULL )
    BIO_free(bcert);
  if ( *stap != 0 )
    {
      freecrf(cf);
      if ( freex )
	X509_CRL_free(x);
      cf = NULL;
    }
  *xp = x;
  return(cf);
}

/*
  Profile checking code by Mudge
*/

#ifdef DEBUG

static void debug_chk_printf(char *str, int val, int cert_type)
{
  char *ta_cert_str = "TA_CERT";
  char *ca_cert_str = "CA_CERT";
  char *ee_cert_str = "EE_CERT";
  char *un_cert_str = "UNK_CERT";
  char *cert_str;
  char *val_str;
  char other_val_str[32];
  char other_cert_str[32];

  cert_str = val_str = NULL;
  memset(other_cert_str, '\0', sizeof(other_cert_str));
  memset(other_val_str, '\0', sizeof(other_val_str));

  switch(cert_type) {
    case CA_CERT:
      cert_str = ca_cert_str;
      break;
    case TA_CERT:
      cert_str = ta_cert_str;
      break;
    case EE_CERT:
      cert_str = ee_cert_str;
      break;
    case UN_CERT:
      cert_str = un_cert_str;
      break;
    default:
      snprintf(other_cert_str, sizeof(other_cert_str) - 1,
               "cert type val: %d (\?\?)", cert_type);
      cert_str = other_cert_str;
      break;
  }

  snprintf(other_val_str, sizeof(other_val_str) - 1,
	   "%d", val);
  val_str = other_val_str;

  fprintf(stderr, "%s returned: %s [against: %s]\n", str, val_str, cert_str);
}

#endif

/*************************************************************
 * This is a minimal modification of                         *
 * x509v3_cache_extensions() found in crypt/X509v3/v3_purp.c *
 * what it does is to load up the X509_st struct so one can  *
 * check extensions in the unsigned long flags within that   *
 * structure rather than recursively calling in the ASN.1    *
 * elements until one finds the correct NID/OID              *
 ************************************************************/

static void x509v3_load_extensions(X509 *x)
{
  BASIC_CONSTRAINTS *bs;
  PROXY_CERT_INFO_EXTENSION *pci;
  ASN1_BIT_STRING *usage;
  ASN1_BIT_STRING *ns;
  EXTENDED_KEY_USAGE *extusage;
  X509_EXTENSION *ex;
  int i;

  if(x->ex_flags & EXFLAG_SET)
    return;
#ifndef OPENSSL_NO_SHA
  X509_digest(x, EVP_sha1(), x->sha1_hash, NULL);
#endif
  /* Does subject name match issuer ? */
  if(!X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)))
    x->ex_flags |= EXFLAG_SS;
  /* V1 should mean no extensions ... */
  if(!X509_get_version(x))
    x->ex_flags |= EXFLAG_V1;
  /* Handle basic constraints */
  if((bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL))) {
    if(bs->ca)
      x->ex_flags |= EXFLAG_CA;
    if(bs->pathlen) {
      if((bs->pathlen->type == V_ASN1_NEG_INTEGER) || !bs->ca) {
        x->ex_flags |= EXFLAG_INVALID;
        x->ex_pathlen = 0;
      } else {
        x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
      }
    } else {
      x->ex_pathlen = -1;
    }

    BASIC_CONSTRAINTS_free(bs);
    x->ex_flags |= EXFLAG_BCONS;
  }

  /* Handle proxy certificates */
  if((pci=X509_get_ext_d2i(x, NID_proxyCertInfo, NULL, NULL))) {
    if (x->ex_flags & EXFLAG_CA ||
        X509_get_ext_by_NID(x, NID_subject_alt_name, 0) >= 0
        || X509_get_ext_by_NID(x, NID_issuer_alt_name, 0) >= 0) {
      x->ex_flags |= EXFLAG_INVALID;
    }
    if (pci->pcPathLengthConstraint) {
      x->ex_pcpathlen = ASN1_INTEGER_get(pci->pcPathLengthConstraint);
    } else {
      x->ex_pcpathlen = -1;
    }
    PROXY_CERT_INFO_EXTENSION_free(pci);
    x->ex_flags |= EXFLAG_PROXY;
  }

  /* Handle key usage */
  if((usage=X509_get_ext_d2i(x, NID_key_usage, NULL, NULL))) {
    if(usage->length > 0) {
      x->ex_kusage = usage->data[0];
      if(usage->length > 1)
        x->ex_kusage |= usage->data[1] << 8;
    } else {
      x->ex_kusage = 0;
    }
    x->ex_flags |= EXFLAG_KUSAGE;
    ASN1_BIT_STRING_free(usage);
  }
  x->ex_xkusage = 0;
  if((extusage=X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL))) {
    x->ex_flags |= EXFLAG_XKUSAGE;
    for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
      switch(OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage,i))) {
        case NID_server_auth:
          x->ex_xkusage |= XKU_SSL_SERVER;
          break;

        case NID_client_auth:
          x->ex_xkusage |= XKU_SSL_CLIENT;
          break;

        case NID_email_protect:
          x->ex_xkusage |= XKU_SMIME;
          break;

        case NID_code_sign:
          x->ex_xkusage |= XKU_CODE_SIGN;
          break;

        case NID_ms_sgc:
        case NID_ns_sgc:
          x->ex_xkusage |= XKU_SGC;
          break;

        case NID_OCSP_sign:
          x->ex_xkusage |= XKU_OCSP_SIGN;
          break;

        case NID_time_stamp:
          x->ex_xkusage |= XKU_TIMESTAMP;
          break;

        case NID_dvcs:
          x->ex_xkusage |= XKU_DVCS;
          break;
      }
    }
    sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
  }

  if((ns=X509_get_ext_d2i(x, NID_netscape_cert_type, NULL, NULL))) {
    if(ns->length > 0) x->ex_nscert = ns->data[0];
    else x->ex_nscert = 0;
    x->ex_flags |= EXFLAG_NSCERT;
    ASN1_BIT_STRING_free(ns);
  }

  x->skid =X509_get_ext_d2i(x, NID_subject_key_identifier, NULL, NULL);
  x->akid =X509_get_ext_d2i(x, NID_authority_key_identifier, NULL, NULL);
#ifdef OUT
   /* the crldp element didn't show up in the x509_st until after
      OpenSSL 0.9.8e-dev XX xxx XXXX apparently  */
  /* NOTE */
  /* we check for it manually in the rescert_crldp_chk() function */
  x->crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
#endif
#ifndef OPENSSL_NO_RFC3779
  x->rfc3779_addr =X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);
  x->rfc3779_asid =X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, NULL, NULL);
#endif

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    if (!X509_EXTENSION_get_critical(ex))
      continue;
    if (!X509_supported_extension(ex)) {
      x->ex_flags |= EXFLAG_CRITICAL;
      break;
    }
  }
  x->ex_flags |= EXFLAG_SET;
}

/*
  Check certificate flags against the manifest certificate type
*/

static int rescert_flags_chk(X509 *x, int ct)
{
  unsigned long ta_flags, ta_kusage, ca_flags, ca_kusage, ee_flags, ee_kusage;
  int cert_type;

  ta_flags = (EXFLAG_SET|EXFLAG_SS|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ta_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ca_flags = (EXFLAG_SET|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ca_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ee_flags = (EXFLAG_SET|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ee_kusage = (KU_DIGITAL_SIGNATURE);

  if ( (x->ex_flags == ta_flags) && (x->ex_kusage == ta_kusage) )
    cert_type = TA_CERT;
  else if ( (x->ex_flags == ca_flags) && (x->ex_kusage == ca_kusage) )
    cert_type = CA_CERT;
  else if ( (x->ex_flags == ee_flags) && (x->ex_kusage == ee_kusage) )
    cert_type = EE_CERT;
  else
    cert_type = UN_CERT;
  if ( ct == cert_type )
    return(0);
  else
    return(ERR_SCM_BADFLAGS);
}

/*************************************************************
 * int rescert_version_chk(X509 *)                           *
 *                                                           *
 *  we require v3 certs (which is value 2)                   *
 ************************************************************/

static int rescert_version_chk(X509 *x)
{
  long l;

  l = X509_get_version(x);
  /* returns the value which is 2 to denote version 3 */

#ifdef DEBUG
  printf("rescert_version_check: version %lu\n", l + 1);
#endif
  if (l != 2)  /* see above: value of 2 means v3 */
    return(ERR_SCM_BADVERS);
  else
    return(0);
}

/*************************************************************
 * rescert_basic_constraints_chk(X509 *, int)                *
 *                                                           *
 *  Basic Constraints - critical MUST be present             *
 *    path length constraint MUST NOT be present             *
 *                                                           *
 * Whereas the Huston rescert sidr draft states that         *
 * basic Constraints must be present and must be marked crit *
 * RFC 2459 states that it SHOULD NOT be present for EE cert *
 *                                                           *
 * the certs that APNIC et al have been making have the      *
 * extension present but not marked critical in EE certs     *
 * sooo...                                                   *
 *    If it's a CA cert then it MUST be present and MUST     *
 *    be critical. If it's an EE cert then it MUST be        *
 *    present MUST NOT have the cA flag set and we don't     *
 *    care if it's marked critical or not. awaiting word     *
 *    back from better sources than I if this is correct.    *
 *                                                           *
 ************************************************************/

static int rescert_basic_constraints_chk(X509 *x, int ct)
{
  int i, basic_flag = 0;
  int ex_nid;
  int ret = 0;
  X509_EXTENSION    *ex = NULL;
  BASIC_CONSTRAINTS *bs = NULL;

  /* test the basic_constraints based against either an
     CA_CERT (cert authority), EE_CERT (end entity), or TA_CERT
     (trust anchor) as definied in the X509 Profile for
     resource certificates. */
  switch(ct) {

    case UN_CERT:
#ifdef DEBUG
      /* getting here means we couldn't figure it out above.. */
      fprintf(stderr, "couldn't determine cert_type to test against\n");
#endif
      return(ERR_SCM_INVALARG);
      break;

    case CA_CERT:
    case TA_CERT:
      /* Basic Constraints MUST be present, MUST be
         critical, cA boolean has to be set for CAs */
      for (i = 0; i < X509_get_ext_count(x); i++) {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_basic_constraints) {
          basic_flag++;
   
          if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
            fprintf(stderr,
		    "[basic_const] CA_CERT: basic_constraints NOT critical!\n");
#endif
            ret = ERR_SCM_NCEXT;
            goto skip;
          }

          bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);
          if (!(bs->ca)) {
#ifdef DEBUG
            fprintf(stderr,
		    "[basic_const] testing for CA_CERT: cA boolean NOT set\n");
#endif
            ret = ERR_SCM_NOTCA;
            goto skip;
          }

          if (bs->pathlen) {
#ifdef DEBUG
            fprintf(stderr,
		    "[basic_const] basic constraints pathlen present - profile violation\n");
#endif
            ret = ERR_SCM_BADPATHLEN;
            goto skip;
          }

          BASIC_CONSTRAINTS_free(bs);
	  bs = NULL;
        }
     }
     if (basic_flag == 0) {
#ifdef DEBUG
       fprintf(stderr, "[basic_const] basic_constraints not present\n");
#endif
       return(ERR_SCM_NOBC);
     } else if (basic_flag > 1) {
#ifdef DEBUG
       fprintf(stderr, "[basic_const] mutliple instances of extension\n");
#endif
       return(ERR_SCM_DUPBC);
     } else {
       return(0);
     }
     break; /* should never get to break */

    case EE_CERT:
      /* Basic Constraints MUST be present, we don't check that it
         is marked critical, cA boolean should not be set
         pathlen MUST NOT be present */

      for (i = 0; i < X509_get_ext_count(x); i++) {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_basic_constraints) {
          basic_flag++;

          bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);

          if ((bs->ca)) {
#ifdef DEBUG
            fprintf(stderr, "[basic_const] EE_CERT: cA boolean IS set\n");
#endif
            ret = ERR_SCM_ISCA;
            goto skip;
          }

          if (bs->pathlen) {
#ifdef DEBUG
            fprintf(stderr, "[basic_const] pathlen found, profile violation\n");
#endif
            ret = ERR_SCM_BADPATHLEN;
            goto skip;
          }

          BASIC_CONSTRAINTS_free(bs);
	  bs = NULL;
        }
      }
        if (basic_flag == 0) {
#ifdef DEBUG
          fprintf(stderr, "[basic_const] extension not present\n");
#endif
          return(ERR_SCM_NOBC);
        } else if (basic_flag > 1) {
#ifdef DEBUG
          fprintf(stderr, "[basic_const] multiple instances of extension\n");
#endif
          return(ERR_SCM_DUPBC);
        } else {
          return(0);
        }
    break;
  }
skip:
#ifdef DEBUG
  fprintf(stderr, "[basic_const] jump to return...\n");
#endif
  if (bs)
    BASIC_CONSTRAINTS_free(bs);
  return(ret);
}

/*************************************************************
 * rescert_ski_chk(X509 *)                                   *
 *                                                           *
 *  Subject Key Identifier - non-critical MUST be present    *
 *                                                           *
 *  We don't do anything with the cert_type as this is true  *
 *  of EE, CA, and TA certs in the resrouce cert profile     *
 ************************************************************/

static int rescert_ski_chk(X509 *x)
{

  int ski_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  X509_EXTENSION *ex = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_subject_key_identifier) {
      ski_flag++;
      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "SKI marked as critical, profile violation\n");
#endif
        ret = ERR_SCM_CEXT;
        goto skip;
      }
    }
  }
  if (ski_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[ski] ski extionsion missing\n");
#endif
    return(ERR_SCM_NOSKI);
  } else if (ski_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[ski] multiple instances of ski extension\n");
#endif
    return(ERR_SCM_DUPSKI);
  } else {
    return(0);
  }
skip:
#ifdef DEBUG
  fprintf(stderr, "[ski]jump to return...\n");
#endif
  return(ret);
}

/*************************************************************
 * rescert_aki_chk(X509 *, int)                              *
 *                                                           *
 *  Authority Key Identifier - non-crit MUST be present      *
 *    keyIdentifier - MUST be present except in TA's         *
 *    authorityCertIssuer - MUST NOT be present              *
 *    authorityCertSerialNumber - MUST NOT be present        *
 *                                                           *
 ************************************************************/

static int rescert_aki_chk(X509 *x, int ct)
{
  int aki_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  X509_EXTENSION  *ex = NULL;
  AUTHORITY_KEYID *akid = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_authority_key_identifier) {
      aki_flag++;

      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[aki] critical, profile violation\n");
#endif
        ret = ERR_SCM_CEXT;
        goto skip;
      }

      akid = X509_get_ext_d2i(x, NID_authority_key_identifier, NULL, NULL);
      if (!akid) {
#ifdef DEBUG
        fprintf(stderr, "[aki] could not load aki\n");
#endif
        return(ERR_SCM_NOAKI);
      }

      /* Key Identifier sub field MUST be present in all certs except for
         self signed CA (aka TA) */
      if ( (!akid->keyid) && (ct != TA_CERT)) {
#ifdef DEBUG
        fprintf(stderr, "[aki] key identifier sub field not present\n");
#endif
        ret = ERR_SCM_NOAKI;
        goto skip;
      }

      if (akid->issuer) {
#ifdef DEBUG
        fprintf(stderr,
                "[aki_chk] authorityCertIssuer is present = violation\n");
#endif
        ret = ERR_SCM_ACI;
        goto skip;
      }

      if (akid->serial) {
#ifdef DEBUG
        fprintf(stderr,
                "[aki_chk] authorityCertSerialNumber is present = violation\n");
#endif
        ret = ERR_SCM_ACSN;
        goto skip;
      }
    }
  }

  if (akid)
    {
      AUTHORITY_KEYID_free(akid);
      akid = NULL;
    }

  if (aki_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[aki_chk] missing AKI extension\n");
#endif
    return(ERR_SCM_NOAKI);
  } else if (aki_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[aki_chk] duplicate AKI extensions\n");
#endif
    return(ERR_SCM_DUPAKI);
  } else {
    return(0);
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[ski]jump to return...\n");
#endif
  if (akid)
    AUTHORITY_KEYID_free(akid);
  return(ret);
}

/*************************************************************
 * rescert_key_usage_chk(X509 *)                             *
 *                                                           *
 *  Key Usage - critical - MUST be present                   *
 *    TA|CA - keyCertSign and CRLSign only                   *
 *    EE - digitalSignature only                             *
 *                                                           *
 ************************************************************/

static int rescert_key_usage_chk(X509 *x)
{
  int kusage_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  X509_EXTENSION *ex = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
  
    if (ex_nid == NID_key_usage) {
      kusage_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[kusage] not marked critical, violation\n");
#endif
        ret = ERR_SCM_NCEXT;
        goto skip;
      }

      /* I don't like that I'm depending upon other OpenSSL components
         for the populating of a parent structure for testing this,
         but running out of time and there's no KEY_USAGE_st and I
         don't have the time to parse the ASN1_BIT_STRING (probably
         trivial but don't know it yet...). Check asn1/asn1.h for
         struct asn1_string_st, x509v3/v3_bitst.c, and get the
         ASN1_BIT_STRING via usage=X509_get_ext_d2i(x, NID_key_usage,
         NULL, NULL) if we end up doing this correctly.
         */
    }
  }

  if (kusage_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[key_usage] missing Key Usage extension\n");
#endif
    return(ERR_SCM_NOKUSAGE);
  } else if (kusage_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[key_usage] multiple key_usage extensions\n");
#endif
    return(ERR_SCM_DUPKUSAGE);
  } else {
    return(0);
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[key_usage] jump to...\n");
#endif
  return(ret);
}

/*************************************************************
 * rescert_crldp_chk(X509 *, int)                            *
 *                                                           *
 *  CRL Distribution Points - non-crit -                     *
 *  MUST be present unless the CA is self-signed (TA) in     *
 *  which case it MUST be omitted.                           *
 *                                                           *
 *  CRLissuer MUST be omitted                                *
 *  reasons MUST be omitted                                  *
 *                                                           *
 ************************************************************/

static int rescert_crldp_chk(X509 *x, int ct)
{
  int crldp_flag = 0, uri_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  STACK_OF(DIST_POINT) *crldp = NULL;
  DIST_POINT     *dist_st = NULL;
  X509_EXTENSION *ex = NULL;
  GENERAL_NAME   *gen_name = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_crl_distribution_points) {
      crldp_flag++;
#ifdef notdef  // MCR removed this test
      if (ct == TA_CERT) {
#ifdef DEBUG
        fprintf(stderr, "[crldp] crldp found in self-signed cert\n");
#endif
        ret = ERR_SCM_CRLDPTA;
        goto skip;
      }
#endif
      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[crldp] marked critical, violation\n");
#endif
        ret = ERR_SCM_CEXT;
        goto skip;
      }

    }
  }

  if (crldp_flag == 0) {
    if (ct == TA_CERT) {  /* must be omitted if TA */
      ret = 0;
      goto skip;
    }
#ifdef DEBUG
    fprintf(stderr, "[crldp] missing crldp extension\n");
#endif
    return(ERR_SCM_NOCRLDP);
  } else if (crldp_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] multiple crldp extensions\n");
#endif
    return(ERR_SCM_DUPCRLDP);
  }

  /* we should be here if NID_crl_distribution_points was found,
     it was not marked critical, and there was only one instance of it.

     I think rob's code is doing this right so I'm lifting his
     checks from rcynic.c */

  crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
  if (!crldp) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] could not retrieve crldp extension\n");
#endif
    return(ERR_SCM_NOCRLDP);
  } else if (sk_DIST_POINT_num(crldp) != 1) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] incorrect number of STACK_OF(DIST_POINT)\n");
#endif
    ret = ERR_SCM_DUPCRLDP;
    goto skip;
  }

  dist_st = sk_DIST_POINT_value(crldp, 0);
  if (dist_st->reasons || dist_st->CRLissuer || !dist_st->distpoint
      || dist_st->distpoint->type != 0) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] incorrect crldp sub fields\n");
#endif
    ret = ERR_SCM_CRLDPSF;
    goto skip;
  }

  for (i=0; i < sk_GENERAL_NAME_num(dist_st->distpoint->name.fullname); i++) {
    gen_name = sk_GENERAL_NAME_value(dist_st->distpoint->name.fullname, i);
    if (!gen_name) {
#ifdef DEBUG
      fprintf(stderr, "[crldp] error retrieving distribution point name\n");
#endif
      ret = ERR_SCM_CRLDPNM;
      goto skip;
    }
    /* all of the general names must be of type URI */
    if (gen_name->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[crldp] general name of non GEN_URI type found\n");
#endif
      ret = ERR_SCM_BADCRLDP;
      goto skip;
    }

    if (!strncasecmp((const char *)gen_name->d.uniformResourceIdentifier->data,
                     (const char *)"rsync://", sizeof("rsync://") -1))  {
      /* printf("uri: %s\n", gen_name->d.uniformResourceIdentifier->data); */
      uri_flag++;
    }
  }

  if (uri_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] no general name of type URI\n");
#endif
    ret = ERR_SCM_CRLDPNM;
    goto skip;
  } else {
    if (crldp)
      {
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	crldp = NULL;
      }
    return(0);
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[crldp] jump to return...\n");
#endif
  if (crldp)
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  return(ret);
}

/*************************************************************
 * rescert_aia_chk(X509 *, int)                              *
 *                                                           *
 *  Authority Information Access - non-crit - MUST           *
 *     be present                                            *
 *     in the case of TAs this SHOULD be omitted             *
 *                                                           *
 ************************************************************/

static int rescert_aia_chk(X509 *x, int ct)
{
  int info_flag = 0, uri_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  int aia_oid_len;
  AUTHORITY_INFO_ACCESS *aia = NULL;
  ACCESS_DESCRIPTION    *adesc = NULL;
  X509_EXTENSION *ex;
  static const unsigned char aia_oid[] =
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};

  aia_oid_len = sizeof(aia_oid);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_info_access) {
      info_flag++;

      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[aia] marked critical, violation\n");
#endif
        ret = ERR_SCM_CEXT;
        goto skip;
      }

    }
  }

  if (info_flag == 0) {
    if (ct == TA_CERT) {  /* SHOULD be omitted if TA */
      ret = 0;
      goto skip;
    } else {
#ifdef DEBUG
      fprintf(stderr, "[aia] missing aia extension\n");
#endif
      return(ERR_SCM_NOAIA);
    }
  } else if (info_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[aia] multiple aia extensions\n");
#endif
    return(ERR_SCM_DUPAIA);
  }

  /* we should be here if NID_info_access was found,
     it was not marked critical, and there was only one instance of it.

     Rob's code from rcynic shows how to get the URI out of the aia...
     so lifting his teachings.  Though he should be using strncasecmp
     rather than strncmp as I don't think there are any specifications
     requiring the URI to be case sensitive.
  */

  aia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL);
  if (!aia) {
#ifdef DEBUG
    fprintf(stderr, "[aia] could not retrieve aia extension\n");
#endif
    return(ERR_SCM_NOAIA);
  }

  for (i=0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
    adesc = sk_ACCESS_DESCRIPTION_value(aia, i);
    if (!adesc) {
#ifdef DEBUG
      fprintf(stderr, "[aia] error retrieving access description\n");
#endif
      ret = ERR_SCM_NOAIA;
      goto skip;
    }
    /* URI form of object identification in AIA */
    if (adesc->location->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[aia] access type of non GEN_URI found\n");
#endif
      ret = ERR_SCM_BADAIA;
      goto skip;
    }

    if ( (adesc->method->length == aia_oid_len) &&
         (!memcmp(adesc->method->data, aia_oid, aia_oid_len)) &&
         (!strncasecmp((const char *)adesc->location->d.uniformResourceIdentifier->data, (const char *)"rsync://", sizeof("rsync://") - 1)) ) {
      uri_flag++;
    }
  }

  if (uri_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[aia] no aia name of type URI rsync\n"); 
#endif
    ret = ERR_SCM_BADAIA;
    goto skip;
  } else {
    ret = 0;
    goto skip;
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[aia] jump to return...\n");
#endif
  if (aia)
    sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);
  return(ret);
}

/*************************************************************
 * rescert_sia_chk(X509 *, int)                              *
 *                                                           *
 *  Subject Information Access -                             *
 *    CA - non-critical - MUST be present                    *
 *    non-CA - MUST NOT be present                           *
 *                                                           *
 ************************************************************/

static int rescert_sia_chk(X509 *x, int ct)
{
  int sinfo_flag = 0, uri_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  int sia_oid_len;
  size_t len = 0;
  AUTHORITY_INFO_ACCESS *sia = NULL;
  ACCESS_DESCRIPTION    *adesc = NULL;
  X509_EXTENSION *ex;
  char c;
  static const unsigned char sia_oid[] =
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};

  sia_oid_len = sizeof(sia_oid);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_sinfo_access) {
      sinfo_flag++;

      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[sia] marked critical, violation\n");
#endif
        ret = ERR_SCM_CEXT;
        goto skip;
      }

    }
  }

  if (sinfo_flag == 0) {
    if (ct == EE_CERT) {  /* MAY be omitted if not CA */
      ret = 0;
      goto skip;
    } else {
#ifdef DEBUG
      fprintf(stderr, "[sia] missing sia extension\n");
#endif
      return(ERR_SCM_NOSIA);
    }
  } else if (sinfo_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[sia] multiple sia extensions\n");
#endif
    return(ERR_SCM_DUPSIA);
  }

  /* we should be here if NID_sinfo_access was found,
     it was not marked critical, and there was only one instance of it.

     Rob's code from rcynic shows how to get the URI out of the sia...
     so lifting his teachings.  Though he should be using strncasecmp
     rather than strncmp as I don't think there are any specifications
     requiring the URI to be case sensitive. Additionally, there were
     no checks in his code to make sure that the RSYNC URI MUST use a
     trailing '/' in the URI.
 
  */

  sia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL);
  if (!sia) {
#ifdef DEBUG
    fprintf(stderr, "[sia] could not retrieve sia extension\n");
#endif
    return(ERR_SCM_NOSIA);
  }

  for (i=0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
    adesc = sk_ACCESS_DESCRIPTION_value(sia, i);
    if (!adesc) {
#ifdef DEBUG
      fprintf(stderr, "[sia] error retrieving access description\n");
#endif
      ret = ERR_SCM_NOSIA;
      goto skip;
    }
    /* URI form of object identification in SIA */
    if (adesc->location->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[sia] access type of non GEN_URI found\n");
#endif
      ret = ERR_SCM_BADSIA;
      goto skip;
    }

    if ( (adesc->method->length == sia_oid_len) &&
         (!memcmp(adesc->method->data, sia_oid, sia_oid_len)) &&
         (!strncasecmp((const char *)adesc->location->d.uniformResourceIdentifier->data, (const char *)"rsync://", sizeof("rsync://") - 1)) ) {
      /* it's the right length, right oid, and it _starts_ with
         the correct url method... does it end with a trailing '/'? */
      len = strlen((const char *)adesc->location->d.uniformResourceIdentifier->data);
      /* don't want a wrap case if len comes back 0 */
      if (len == 0) {
        ret = ERR_SCM_NOSIA;
#ifdef DEBUG
        fprintf(stderr, "[sia] ACCESS DESCRIPTOR lengh 0\n");
#endif
        goto skip;
      }
      c = adesc->location->d.uniformResourceIdentifier->data[len - 1];
      if (c == '/')
        uri_flag++;
      else {
#ifdef DEBUG
        fprintf(stderr, "[sia] rsync uri in CA cert without trailing /\n");
#endif
        ret = ERR_SCM_BADSIA;
        goto skip;
      }
    }
  }

  if (uri_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[sia] no sia name of type URI rsync\n");
#endif
    ret = ERR_SCM_BADSIA;
    goto skip;
  } else {
    ret = 0;
    goto skip;
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[sia] jump to return...\n");
#endif
  if (sia)
    sk_ACCESS_DESCRIPTION_pop_free(sia, ACCESS_DESCRIPTION_free);
  return(ret);
}

/*************************************************************
 * rescert_cert_policy_chk(X509 *)                           *
 *                                                           *
 *  Certificate Policies - critical - MUST be present        *
 *    PolicyQualifiers - MUST NOT be used in this profile    *
 *    OID Policy Identifier value: "1.3.6.1.5.5.7.14.2"      *
 *                                                           *
 ************************************************************/

static int rescert_cert_policy_chk(X509 *x)
{

  int policy_flag = 0;
  int i;
  int ex_nid;
  int ret = 0;
  int len;
  X509_EXTENSION *ex = NULL;
  CERTIFICATEPOLICIES *ex_cpols = NULL;
  POLICYINFO *policy;
  char policy_id_str[32];
  char *oid_policy_id = "1.3.6.1.5.5.7.14.2\0";
  int policy_id_len = strlen(oid_policy_id);

  memset(policy_id_str, '\0', sizeof(policy_id_str));

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_certificate_policies) {
      policy_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[policy] not marked as critical\n");
#endif
        ret = ERR_SCM_NCEXT;
        goto skip;
      }
    }
  }
  if (policy_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[policy] policy extionsion missing\n");
#endif
    ret = ERR_SCM_NOPOLICY;
    goto skip;
  } else if (policy_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[policy] multiple instances of policy extension\n");
#endif
    ret = ERR_SCM_DUPPOLICY;
    goto skip;
  }

  /* we should be here if policy_flag == 1, it was marked critical,
     and there was only one instance of it. */
  ex_cpols = X509_get_ext_d2i(x, NID_certificate_policies, NULL, NULL);
  if (!ex_cpols) {
#ifdef DEBUG
    fprintf(stderr, "[policy] policies present but could not retrieve\n");
#endif
    ret = ERR_SCM_NOPOLICY;
    goto skip;
  }

  if (sk_POLICYINFO_num(ex_cpols) != 1) {
#ifdef DEBUG
    fprintf(stderr, "[policy] incorrect number of policies\n");
#endif
    ret = ERR_SCM_DUPPOLICY;
    goto skip;
  }

  policy = sk_POLICYINFO_value(ex_cpols, 0);
  if (!policy) {
#ifdef DEBUG
    fprintf(stderr, "[policy] could not retrieve policyinfo\n");
#endif
    ret = ERR_SCM_NOPOLICY;
    goto skip;
  }

  if (policy->qualifiers) {
#ifdef DEBUG
    fprintf(stderr, "[policy] must not contain PolicyQualifiers\n");
#endif
    ret = ERR_SCM_POLICYQ;
    goto skip;
  }

  len = i2t_ASN1_OBJECT(policy_id_str, sizeof(policy_id_str), policy->policyid);

  if ( (len != policy_id_len) || (strcmp(policy_id_str, oid_policy_id)) ) {
#ifdef DEBUG
    fprintf(stderr, "len: %d value: %s\n", len, policy_id_str);
    fprintf(stderr, "[policy] OID Policy Identifier value incorrect\n");
#endif
    ret = ERR_SCM_BADOID;
    goto skip;
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[policy] jump to return...\n");
#endif

  if (ex_cpols)
    sk_POLICYINFO_pop_free(ex_cpols, POLICYINFO_free);

  return(ret);
}

/*************************************************************
 * rescert_ip_resources_chk(X509 *)                          *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           *
 ************************************************************/

static int rescert_ip_resources_chk(X509 *x)
{
  int ipaddr_flag = 0;
  int i;
  int ex_nid;
  X509_EXTENSION *ex = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_sbgp_ipAddrBlock) {
      ipaddr_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[IP res] not marked as critical\n");
#endif
        return(ERR_SCM_NCEXT);
      }
    }
  }

  if (!ipaddr_flag) {
#ifdef DEBUG
    fprintf(stderr, "[IP res] did not contain IP Resources ext\n");
    fprintf(stderr, "could be ok if AS resources are present and correct\n");
#endif
    return(0);
  } else if (ipaddr_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[IP res] multiple instances of IP resources extension\n");
#endif
    return(ERR_SCM_DUPIP);
  }

  return(0);
}

/*************************************************************
 * rescert_as_resources_chk(X509 *)                          *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           *
 ************************************************************/

static int rescert_as_resources_chk(X509 *x)
{
  int asnum_flag = 0;
  int i;
  int ex_nid;
  X509_EXTENSION *ex = NULL;                                         

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_sbgp_ipAddrBlock) {
      asnum_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[AS res] not marked as critical\n");
#endif
        return(ERR_SCM_NCEXT);
      }
    }
  }

  if (!asnum_flag) {
#ifdef DEBUG
    fprintf(stderr, "[AS res] did not contain IP Resources ext\n");
    fprintf(stderr, "could be ok if IP resources are present and correct\n");
#endif
    return(0);
  } else if (asnum_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[AS res] multiple instances of AS resources extension\n");
#endif
    return(ERR_SCM_DUPAS);
  }

  return(0);
}

/*************************************************************
 * rescert_ip_asnum_chk(X509 *)                              *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           *
 * Note that OpenSSL now include Rob's code for 3779         *
 * extensions and it looks like the check and load them      *
 * correctly. All we should need to do is to make sure that  *
 * this function makes sure one or the other (ip or as res)  *
 * is present and then call simple routines to make sure     *
 * there are not multiple instances of the same extension    *
 * and that the extension(s) present are marked critical.    *
 ************************************************************/

static int rescert_ip_asnum_chk(X509 *x)
{
  int ret = 0;

  if ( (x->rfc3779_addr) || (x->rfc3779_asid) ) {
    if (x->rfc3779_addr) {
      ret = rescert_ip_resources_chk(x);
      if ( ret < 0 )
        return(ret);
    }
    if (x->rfc3779_asid) {
      ret = rescert_as_resources_chk(x);
      if ( ret < 0 )
        return(ret);
    }
  } else {
    /* doesn't have IP resources OR AS Resources */
    return(ERR_SCM_NOIPAS);
  }

  return(0);
}

/* from x509v3/v3_purp.c */
static int res_nid_cmp(int *a, int *b)
{
  return *a - *b;
}

/* this function is a minimal change to OpenSSL's
   X509_supported_extension() function from
   crypto/x509v3/v3_purp.c

   The modifications are a change in the supported nids
   array to match the Resource Certificate Profile sepecification

   This function is used to catch extensions that
   might be marked critical that we were not expecting. You should
   only pass this criticals.

   Criticals in Resource Certificate Profile:
       Basic Constraints
       Key Usage
       Certificate Policies
        (NOT Subject Alt Name, which is going to be removed
         anyway in the future from this profile)
       IP Resources
       AS Resources
*/

static int rescert_crit_ext_chk(X509_EXTENSION *ex)
{
  /* This table is a list of the NIDs of supported extensions:
   * that is those which are used by the verify process. If
   * an extension is critical and doesn't appear in this list
   * then the verify process will normally reject the certificate.
   * The list must be kept in numerical order because it will be
   * searched using bsearch.
   */

  static int supported_nids[] = {
            NID_key_usage,          /* 83 */
            NID_basic_constraints,  /* 87 */
            NID_certificate_policies, /* 89 */
            NID_sbgp_ipAddrBlock,   /* 290 */
            NID_sbgp_autonomousSysNum, /* 291 */
  };

  int ex_nid;

  ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
 
  if (ex_nid == NID_undef)                              
    return ERR_SCM_BADEXT;

  if (OBJ_bsearch((char *)&ex_nid, (char *)supported_nids,
                  sizeof(supported_nids)/sizeof(int), sizeof(int),
                  (int (*)(const void *, const void *))res_nid_cmp))
    return(0);
  return(ERR_SCM_BADEXT);
}

/*************************************************************
 * rescert_criticals_present_chk(X509 *)                     *
 *                                                           *
 *  This iterates through what we expect to be critical      *
 *  extensions present in TA,CA,EE certs. If there is a crit *
 *  extension that we don't recognize it fails. If there is  *
 *  an extension that we expect to see as a crit or if an    *
 *  extension that is supposed to be marked crit is marked   *
 *  non-crit it fails.                                       *
 *                                                           *
 * currently stubbed... don't know if *we* should be doing   *
 * this check or if it should be done elsewhere.             *
 ************************************************************/

static int rescert_criticals_chk(X509 *x)
{
  int ret = 0;
  int i;
  X509_EXTENSION *ex = NULL;

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    if (!X509_EXTENSION_get_critical(ex))
      continue;
    ret = rescert_crit_ext_chk(ex);
    if ( ret < 0 )
      return(ret);
  }

  return(0);
}

/**********************************************************
 * profile_check(X509 *, int cert_type)                   *
 *  This function makes sure the required base eleme ts   *
 *  are present within the certificate.                   *
 *   cert_type can be one of CA_CERT, EE_CERT, TA_CERT    *
 *                                                        *
 *  Basic Constraints - critical MUST be present          *
 *    path length constraint MUST NOT be present          *
 *                                                        *
 *  Subject Key Identifier - non-critical MUST be present *
 *                                                        *
 *  Authority Key Identifier - non-crit MUST be present   *
 *    keyIdentifier - MUST be present except in TA's      *
 *      (TA versus EE,CA checks performed elsewhere)      *
 *    authorityCertIssuer - MUST NOT be present           *
 *    authorityCertSerialNumber - MUST NOT be present     *
 *                                                        *
 *  Key Usage - critical - MUST be present                *
 *    ({CA,EE} specific checks performed elsewhere)       *
 *    CA - keyCertSign and CRLSign only                   *
 *    EE - digitalSignature only                          *
 *                                                        *
 *  CRL Distribution Points - non-crit - MUST be present  *
 *                                                        *
 *  Authority Information Access - non-crit - MUST        *
 *     be present                                         *
 *    (in the case of TAs this SHOULD be omitted - this   *
 *    check performed elsewhere)                          *
 *                                                        *
 *  Subject Information Access -                          *
 *    CA - non-critical - MUST be present                 *
 *    non-CA - MUST NOT be present                        *
 *      Will check for this elsewhere.                    *
 *                                                        *
 *  Certificate Policies - critical - MUST be present     *
 *    PolicyQualifiers - MUST NOT be used in this profile *
 *    OID Policy Identifier value: "1.3.6.1.5.5.7.14.2"   *
 *                                                        *
 *  Subject Alt Name - optional, not checked for          *
 *                                                        *
 *  IP Resources, AS Resources - critical - MUST have one *
 *   of these or both. In the case of one, if present     *
 *   marked as critical                                   *
 *********************************************************/

int rescert_profile_chk(X509 *x, int ct)
{
  int ret = 0;

  if ( x == NULL || ct == UN_CERT )
    return(ERR_SCM_INVALARG);
  /* load the X509_st extension values */
  x509v3_load_extensions(x);

  if ( (x->ex_flags & EXFLAG_INVALID) != 0 ||
       (x->ex_flags & EXFLAG_SET) == 0 )
    return(ERR_SCM_BADEXT);

  ret = rescert_flags_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_flags_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_version_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_version_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_basic_constraints_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_basic_constraints_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_ski_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_ski_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_aki_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_aki_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_key_usage_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_key_usage_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_crldp_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_crldp_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_aia_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_aia_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_sia_chk(x, ct);
#ifdef DEBUG
  debug_chk_printf("rescert_sia_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_cert_policy_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_cert_policy_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_ip_asnum_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_ip_asnum_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  ret = rescert_criticals_chk(x);
#ifdef DEBUG
  debug_chk_printf("rescert_criticals_chk", ret, ct);
#endif
  if ( ret < 0 )
    return(ret);

  return(0);
}
