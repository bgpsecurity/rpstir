/*
  $Id$
*/

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

int roaValidate(ROA *r)
{
  // Make sure that the ROA meets the provisions outlined in 
  // Kent/Kong ROA IETF draft

  // Validate ROA constants
  // check that roa->content->version == 3
  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  // check that roa->content->encapContentInfo->eContentType ==
  //   routeOriginAttestation (= OID 1.2.240.113549.1.9.16.1.24)
  // check that roa->content->crls == NULL
  // check that roa->content->signerInfoStruct->version = 3
  // check that roa->content->signerInfoStruct->digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  // check that roa->content->signerInfoStruct->signedAttrs = NULL
  // check that roa->content->signerInfoStruct->signatureAlgorithm == 
  //   sha256WithRSAEncryption (= OID 1.2.240.113549.1.1.11)
  // check that roa->content->signerInfoStruct->unsignedAttrs = NULL

  // Validate ROA variables
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->asID == a nonzero integer
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressFamily == {IPv4, IPv6}
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressPrefix == validIP
  //  - OR -
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressRange->{min,max} ==
  //    validIP (AND VALID RANGE?)
  // check that roa->content->signerInfoStruct->sid ISA subjectKeyIdentifier

}

int roaValidate2(ROA *r, X509 *x)
{
  // if (certificate exists in roa)
  // -  ignore it
  // -  Or check the certificate against x (optional)
  // Assume cert validity, because by virtue of having been extracted, it is reputable
  // Check that roa->envelope->SKI = x->SKI
  // IPAddresses in ROA subset of IPAddresses in cert
  // Check AS# is listed in cert
}
*/
