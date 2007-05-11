/*
  $Id$
*/

#include "roa_utils.h"

/*
  This file contains the functions that semantically validate the ROA.
  Any and all syntactic validation against existing structures is assumed
  to have been performed at the translation step (see roa_serialize.c).
*/

// ROA_utils.h contains the headers for including these functions
/*
// We're refraining from defining IPAddr until we know what CG gives us
// This function validates IPv4 IP addresses
int IPv4Validate(IPAddr* ipaddr)
{
  // Checks to make sure all 4 subvalues are in range (0-255)
  // returns success or failure
}

// This function validates IPv6 IP addresses
int IPv6Validate(IPAddr* ipaddr)
{
  // Checks to make sure all 8 subvalues are in range (0-ffff)
  // returns success or failure
}

// This function validates ranges of IPv4 IP addresses
int IPv4ValidateRange(IPAddr* ipaddrmin, IPAddr* ipaddrmax)
{
  // Validate addresses
  // Checks to make sure min < max
  // returns success or failure
}

// This function validates ranges of IPv6 IP addresses
int IPv6ValidateRange(IPAddr* ipaddrmin, IPAddr* ipaddrmax)
{
  // Validate addresses
  // Checks to make sure min < max
  // returns success or failure
}
*/

// JFG - Finish commented-out functions
int validateIPContents()
{
  // Call subfunctions as required to assure that ranges/prefixes
  // only overlap per legitimate rules as defined by IETF
  return TRUE;
}

int testSubsetIPContents()
{
  // Call subfunctions as required to assure that ranges/prefixes
  // fall into subset of cert's set of prefixes
  return TRUE;
}

// JFG - link in appropriate parts of OpenSSL for above and below
// instead of these dummy functions:
//long ASN1_INTEGER_ge(ASN1_INTEGER* a)
//{
//  return 0;
//}
//
//int sk_ASIdOrRange_nu(ASIdOrRange *aor)
//{
//  return 0;
//}
//
//ASIdOrRange *sk_ASIdOrRange_valu(ASIdOrRange *aor, int which)
//{
//  return 0;
//}

int roaValidate(struct ROA *r)
{
  // Make sure that the ROA meets the provisions outlined in 
  // Kent/Kong ROA IETF draft
  int iRes = 0;
  int iSize = 0;
  long iAS_ID = 0;
  long iVersion = 0;
  char *cOID = NULL;

  /////////////////////////////////////////////////////////////
  // Validate ROA constants
  /////////////////////////////////////////////////////////////

  // check that roa->content->version == 3
  iRes = read_casn_num(&(r->content.content.version.self), &iVersion);
  if ((0 > iRes) ||
      (iVersion != 3))
    return FALSE;

  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  iRes = readvsize_objid(&(r->content.content.digestAlgorithms.digestAlgorithmIdentifier.algorithm), &cOID);
  if (0 > iRes)
    return FALSE;
  if (0 != strcmp(id_sha256, cOID))
    {
      free(cOID);
      return FALSE;
    }
  free(cOID);

  // check that roa->content->encapContentInfo->eContentType ==
  //   routeOriginAttestation (= OID 1.2.240.113549.1.9.16.1.24)
  iRes = readvsize_objid(&(r->content.content.encapContentInfo.eContentType), &cOID);
  if (0 > iRes)
    return FALSE;
  if (0 != strcmp(routeOriginAttestation, cOID))
    {
      free(cOID);
      return FALSE;
    }
  free(cOID);

  // check that roa->content->crls == NULL
  // JFG - Ask Charlie what the right way to do this would be.

  // check that roa->content->signerInfoStruct->version = 3
  iRes = read_casn_num(&(r->content.content.signerInfos.signerInfo.version.self), &iVersion);
  if ((0 > iRes) ||
      (iVersion != 3))
    return FALSE;

  // check that roa->content->signerInfoStruct->digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  iRes = readvsize_objid(&(r->content.content.signerInfos.signerInfo.digestAlgorithm.algorithm), &cOID);
  if (0 > iRes)
    return FALSE;
  if (0 != strcmp(id_sha256, cOID))
    {
      free(cOID);
      return FALSE;
    }
  free(cOID);

  // check that roa->content->signerInfoStruct->signedAttrs = NULL
  // JFG - Ask Charlie what the right way to do this would be.

  // check that roa->content->signerInfoStruct->signatureAlgorithm == 
  //   sha256WithRSAEncryption (= OID 1.2.240.113549.1.1.11)
  iRes = readvsize_objid(&(r->content.content.signerInfos.signerInfo.signatureAlgorithm.algorithm), &cOID);
  if (0 > iRes)
    return FALSE;
  if (0 != strcmp(id_sha_256WithRSAEncryption, cOID))
    {
      free(cOID);
      return FALSE;
    }
  free(cOID);

  // check that roa->content->signerInfoStruct->unsignedAttrs = NULL
  // JFG - Ask Charlie what the right way to do this would be.

  /////////////////////////////////////////////////////////////
  // Validate ROA variables
  /////////////////////////////////////////////////////////////

  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->asID == a nonzero integer
  iRes = read_casn_num(&(r->content.content.signerInfos.signerInfo.version.self), &iAS_ID);
  if ((0 > iRes) ||
      (iAS_ID <= 0))
    return FALSE;  

  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressFamily == {IPv4, IPv6}
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressPrefix == validIP
  //  - OR -
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressRange->{min,max} ==
  //    validIP (AND VALID RANGE?)
  iRes = validateIPContents();
  if (FALSE == iRes)
    return FALSE;

  // check that roa->content->signerInfoStruct->sid ISA subjectKeyIdentifier
  //   (really just a length check, as byte content is arbitrary)
  iSize = vsize_casn(&(r->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier));
  if (20 != iSize)
    return FALSE;

  return TRUE;
}

int roaValidate2(struct ROA *r, X509 *x)
{
  int i = 0;
  int iRes = 0;

  int iCertSKISize = 0;
  int iROASKISize = 0;
  unsigned char* cSID = NULL;

  long iAS_ID = 0;
  int iASNumCount = 0;
  int iASFound = FALSE;
  ASIdOrRange *asStruct = NULL;

  // if (certificate exists in roa)
  // -  ignore it
  // -  Or check the certificate against x (optional)
  // JFG - We're skipping this step for now; come back to it later as desired

  // JFG - Insert test of cryptographic validity of contents against signature

  /////////////////////////////////////////////////////////////////
  // We get to assume cert validity up the chain, because by virtue
  //  of having been extracted, it is reputable
  /////////////////////////////////////////////////////////////////

  // Check that roa->envelope->SKI = x->SKI
  iCertSKISize = x->skid->length;
  iROASKISize = vsize_casn(&(r->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier));
  if ((20 != iCertSKISize) ||
      (20 != iROASKISize))
    return FALSE;
  iRes = readvsize_casn(&(r->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier), &cSID);
  if ((0 > iRes) ||
      (NULL == cSID))
    return FALSE;

  for (i = 0; i < iROASKISize; i++)
    {
      if (cSID[0] != x->skid->data[i])
	return FALSE;
    }

  // Check AS# is listed in cert
  iRes = read_casn_num(&(r->content.content.encapContentInfo.eContent.roa.asID), &iAS_ID);
  if (0 > iRes)
    return FALSE;

  iASNumCount = sk_ASIdOrRange_num(x->rfc3779_asid->asnum->u.asIdsOrRanges);
  if (0 > iRes)
    return FALSE;

  iASFound = FALSE;
  for (i = 0; (i < iASNumCount) && (FALSE == iASFound); i++)
    {
      asStruct = sk_ASIdOrRange_value(x->rfc3779_asid->asnum->u.asIdsOrRanges, i);
      if (ASIdOrRange_id == asStruct->type)
	{
	  if (ASN1_INTEGER_get(asStruct->u.id) == iAS_ID)
	    iASFound = TRUE;
	}
      else if (ASIdOrRange_range == asStruct->type)
	{
	  if ((ASN1_INTEGER_get(asStruct->u.range->min) <= iAS_ID) &&
	      (ASN1_INTEGER_get(asStruct->u.range->max) >= iAS_ID))
	    iASFound = TRUE;
	}
    }
  if (FALSE == iASFound)
    return FALSE;

  // IPAddresses in ROA subset of IPAddresses in cert
  iRes = testSubsetIPContents();
  if (FALSE == iRes)
    return FALSE;  

  return FALSE;
}
