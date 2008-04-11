/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner, Joshua Gruenspecht
 *
 * ***** END LICENSE BLOCK ***** */

#include "roa_utils.h"
#include "cryptlib.h"

/*
  This file contains the functions that semantically validate the ROA.
  Any and all syntactic validation against existing structures is assumed
  to have been performed at the translation step (see roa_serialize.c).
*/
#define MINMAXBUFSIZE 20

int check_sig(struct ROA *rp, struct Certificate *certp)
  { 
  CRYPT_CONTEXT pubkeyContext, hashContext;
  CRYPT_PKCINFO_RSA rsakey;
  // CRYPT_KEYSET cryptKeyset;
  struct RSAPubKey rsapubkey;
  int bsize, tmp;
  uchar *c, *buf, hash[40];

  memset(hash, 0, 40);
  RSAPubKey(&rsapubkey, 0);
  readvsize_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey, &c);
  decode_casn(&rsapubkey.self, &c[1]);  // [1] to skip 1st byte in BIT STRING
  free(c);
  bsize = vsize_casn(&rp->content.signedData.encapContentInfo.eContent.self);
  buf = (uchar *)calloc(1, bsize);
  tmp = read_casn(&rp->content.signedData.encapContentInfo.eContent.self, buf);
    
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptCreateContext(&pubkeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
  cryptEncrypt(hashContext, buf, bsize);
  cryptEncrypt(hashContext, buf, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &tmp);
  cryptInitComponents(&rsakey, CRYPT_KEYTYPE_PUBLIC);
  free(buf);
  bsize = readvsize_casn(&rsapubkey.modulus, &buf);
  c = buf;
  if (!*buf)
    {
    c++;
    bsize --;
    }  
  cryptSetComponent(rsakey.n, c, bsize * 8);
  bsize = read_casn(&rsapubkey.exponent, buf);
  cryptSetComponent(rsakey.e, buf, bsize * 8);
  free(buf);
  cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
  cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_KEY_COMPONENTS, &rsakey, sizeof(CRYPT_PKCINFO_RSA));
//  cryptKeysetOpen(&cryptKeyset,pubkeyContext, "", CRYPT_KEYOPT_CREATE);
//  cryptAddPublicKey(cryptKeyset, pubkeyContext, "password");
  bsize = size_casn(&rp->content.signedData.signerInfos.signerInfo.self);
  buf = (uchar *)calloc(1, bsize);
  bsize = encode_casn(&rp->content.signedData.signerInfos.signerInfo.self, buf);
  tmp = cryptCheckSignature(buf, bsize, pubkeyContext, hashContext);
  free(buf);
  cryptDestroyContext(pubkeyContext);
  cryptDestroyContext(hashContext);
  cryptEnd();
  delete_casn(&rsapubkey.self);
  if (tmp) return ERR_SCM_INVALSIG;
  return 0;
  }

static void fill_max(uchar *max)
  {
  max[max[1] + 1] |= ((1 << max[2]) - 1);
  } 

static int setup_cert_minmax(struct IPAddressOrRangeA *rpAddrRangep, uchar *cmin, uchar *cmax,
  int fam)
  {
  memset(cmin, 0, MINMAXBUFSIZE);
  memset(cmax, -1, MINMAXBUFSIZE);
  if (fam == 1) fam = 7;
  else if (fam == 2) fam = 19;
  else return ERR_SCM_INVALFAM;
  if (tag_casn(&rpAddrRangep->self) == ASN_SEQUENCE)
    {
    if (size_casn(&rpAddrRangep->addressRange.min) > fam ||
        size_casn(&rpAddrRangep->addressRange.max) > fam) return ERR_SCM_INVALFAM;
    encode_casn(&rpAddrRangep->addressRange.min, cmin);
    encode_casn(&rpAddrRangep->addressRange.max, cmax);
    }
  else 
    {
    if (size_casn(&rpAddrRangep->addressPrefix) > fam) return ERR_SCM_INVALFAM;
    encode_casn(&rpAddrRangep->addressPrefix, cmin);
    encode_casn(&rpAddrRangep->addressPrefix, cmax);
    }
  fill_max(cmax);
  cmin[2] = 0;
  cmax[2] = 0;
  return 0;
  }
 
static int setup_roa_minmax(struct IPAddress *ripAddrp, uchar *rmin, uchar *rmax, int fam)
  {
  memset(rmin, 0, MINMAXBUFSIZE);
  memset(rmax, -1, MINMAXBUFSIZE);
  if (fam == 1) fam = 7;
  else if (fam == 2) fam = 19;
  else return ERR_SCM_INVALFAM;
  if (size_casn(ripAddrp) > fam) return ERR_SCM_INVALFAM;
  encode_casn(ripAddrp, rmin);
  encode_casn(ripAddrp, rmax);
  fill_max(rmax);
  rmin[2] = 0;
  rmax[2] = 0;
  return 0;
  }

static int validateIPContents(struct ROAIPAddrBlocks *ipAddrBlockp)
  {
  uchar rmin[MINMAXBUFSIZE], rmax[MINMAXBUFSIZE], oldmax[MINMAXBUFSIZE], rfam[8];
  struct IPAddress *ipAddrp;
  struct ROAIPAddressFamily *roaipfamp;
  int i = 0;

  for (roaipfamp = &ipAddrBlockp->rOAIPAddressFamily; roaipfamp; 
    roaipfamp = (struct ROAIPAddressFamily *)next_of(&roaipfamp->self))
    {
    if (read_casn(&roaipfamp->addressFamily, rfam) < 0 ||
	rfam[0] != 0 || (rfam[1] != 1 && rfam[1] != 2)) return ERR_SCM_INVALFAM;
    i = rfam[1]; 
    memset(oldmax, 0, sizeof(oldmax));
    for (ipAddrp = &roaipfamp->addresses.iPAddress; ipAddrp; ipAddrp = next_of(ipAddrp))
      {
      if (setup_roa_minmax(ipAddrp, rmin, rmax, i) < 0 ||
        memcmp(&rmin[3], &oldmax[3], sizeof(rmin) - 3) < 0 || 
	  memcmp(&rmax[3 ], &rmin[3], sizeof(rmin) - 3) < 0) return ERR_SCM_INVALIPB;
      }
    }
  return 0;
  }

int roaValidate(struct ROA *rp)
{
  // Make sure that the ROA meets the provisions outlined in 
  // Kent/Kong ROA IETF draft
  int iRes = 0;
  long iAS_ID = 0;
  int  sta = 0;
  char *cOID = NULL;

  /////////////////////////////////////////////////////////////
  // Validate ROA constants
  /////////////////////////////////////////////////////////////

  // check that roa->content->version == 3
  if (diff_casn_num(&rp->content.signedData.version.self, 3) != 0) return ERR_SCM_BADVERS;

  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (num_items(&rp->content.signedData.digestAlgorithms.self) > 1) return ERR_SCM_BADDA;
  if ((iRes = readvsize_objid(&(rp->content.signedData.digestAlgorithms.digestAlgorithmIdentifier.
    algorithm), &cOID)) > 0) iRes = strcmp(cOID, id_sha256);
  if (cOID != NULL) free(cOID);
  if (iRes != 0) return ERR_SCM_BADDA;

  // check that roa->content->encapContentInfo->eContentType ==
  //   routeOriginAttestation (= OID 1.2.240.113549.1.9.16.1.24)
  cOID = NULL;
  if ((iRes = readvsize_objid(&(rp->content.signedData.encapContentInfo.eContentType), &cOID))
    > 0) iRes = strcmp(cOID, id_routeOriginAttestation);
  if (cOID != NULL) free(cOID);
  if (iRes != 0) return ERR_SCM_BADCT;

  // check that roa->content->crls == NULL
  if (size_casn(&rp->content.signedData.crls.self) > 0 ||
     num_items(&rp->content.signedData.signerInfos.self) != 1 ||
     diff_casn_num(&rp->content.signedData.signerInfos.signerInfo.version.self, 3) != 0) 
    return ERR_SCM_BADVERS;

  // check that roa->content->signerInfoStruct->digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  cOID = NULL;
  if ((iRes = readvsize_objid(&rp->content.signedData.signerInfos.signerInfo.digestAlgorithm.
     algorithm, &cOID)) > 0) iRes = strcmp(id_sha256, cOID);
  free(cOID);
  if (iRes != 0) return ERR_SCM_BADCRL;

  if(size_casn(&rp->content.signedData.signerInfos.signerInfo.signedAttrs.self) != 0 ||
     size_casn(&rp->content.signedData.signerInfos.signerInfo.unsignedAttrs.self) != 0) 
    return ERR_SCM_BADATTR;

  // check that roa->content->signerInfoStruct->signatureAlgorithm == 
  //   sha256WithRSAEncryption (= OID 1.2.240.113549.1.1.11)
  if(readvsize_objid(&(rp->content.signedData.signerInfos.signerInfo.signatureAlgorithm.
    algorithm), &cOID) < 0) return ERR_SCM_INVALSIG;
  iRes = strcmp(id_rsadsi_rsaEncryption, cOID);
  free(cOID);
  if (iRes != 0) return ERR_SCM_INVALSIG;

  /////////////////////////////////////////////////////////////
  // Validate ROA variables
  /////////////////////////////////////////////////////////////

  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->asID == a nonzero integer
  if (read_casn_num(&(rp->content.signedData.signerInfos.signerInfo.version.self), &iAS_ID) < 0 ||
      iAS_ID <= 0) return ERR_SCM_INVALASID;

  // check that roa.content.encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressFamily == {IPv4, IPv6}
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressPrefix == validIP
  //  - OR -
  // check that roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressRange->{min,max} ==
  //    validIP (AND VALID RANGE?)
  if ((sta=validateIPContents(&rp->content.signedData.encapContentInfo.eContent.roa.
			      ipAddrBlocks)) < 0) return sta;

  // check that roa->content->signerInfoStruct->sid ISA subjectKeyIdentifier
  //   (really just a length check, as byte content is arbitrary)
  if (vsize_casn(&rp->content.signedData.signerInfos.signerInfo.sid.subjectKeyIdentifier) != 20)
    return ERR_SCM_INVALSKI;

  return 0;
}

int roaValidate2(struct ROA *rp, uchar *certp)
{
  int iRes;
  int sta;
  long iAS_ID = 0;
  long ii, ij;
  struct Extension *extp;
  struct Certificate cert;
  char *oidp;
  struct ASNumberOrRangeA *asNumRp;
  struct IPAddressFamilyA *rpAddrFamp; 
  struct ROAIPAddressFamily *ripAddrFamp;
  struct IPAddressOrRangeA *rpAddrRangep;
  struct IPAddress *ripAddrp;
  uchar cmin[MINMAXBUFSIZE], cmax[MINMAXBUFSIZE], rmin[MINMAXBUFSIZE], rmax[MINMAXBUFSIZE];
  uchar rfam[8], cfam[8];
  int all3 = 0;

  // roaValidate() is an independent function; the caller must call it
  // if the caller wants semantic validation
  //  if (roaValidate(r) == FALSE) return FALSE;
  Certificate(&cert, 0);
  if (decode_casn(&cert.self, certp) < 0) return ERR_SCM_NOTVALID;
  //
 // if (certificate exists in roa)
  // -  ignore it
  // -  Or check the certificate against x (optional)

  /////////////////////////////////////////////////////////////////
  // We get to assume cert validity up the chain, because by virtue
  //  of having been extracted, it is reputable
  /////////////////////////////////////////////////////////////////
  iRes = 0;
  for (extp = (struct Extension *)&cert.toBeSigned.extensions.extension; extp && iRes == 0;
    extp = (struct Extension *)next_of(&extp->self))
    {
    readvsize_objid(&extp->extnID, &oidp);
       // if it's the SKID extension
    if (!memcmp(oidp, id_subjectKeyIdentifier, strlen(oidp)))
      {
      all3 |= 1;      
      // Check that roa->envelope->SKI = cert->SKI
      if (diff_casn(&rp->content.signedData.signerInfos.signerInfo.sid.subjectKeyIdentifier,
        (struct casn *)&extp->extnValue.subjectKeyIdentifier) != 0)
        return ERR_SCM_INVALSKI;
      }
        // or if it's the AS num extension
    else if (!memcmp(oidp, id_pe_autonomousSysNum, strlen(oidp)))
      {
      all3 |= 2;
      if (read_casn_num(&(rp->content.signedData.encapContentInfo.eContent.roa.asID), 
			&iAS_ID) < 0) iRes = ERR_SCM_INVALASID;
      else
        {  // look in cert
        for (asNumRp = &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.aSNumberOrRangeA; 
          asNumRp; asNumRp = (struct ASNumberOrRangeA *)next_of(&asNumRp->self))
          {
          ii = tag_casn(&asNumRp->self);
          if ((ii  == ASN_INTEGER && diff_casn_num(&asNumRp->num, iAS_ID) == 0) ||
            (ii == ASN_SEQUENCE && (diff_casn_num(&asNumRp->range.min, iAS_ID) <= 0) &&
            diff_casn_num(&asNumRp->range.max, iAS_ID) >= 0)) break;
          }
        if (!asNumRp) iRes =  ERR_SCM_INVALASID;
        }
      }
      // or if it's the IP addr extension
    else if (!memcmp(oidp, id_pe_ipAddrBlock, strlen(oidp)))
      {
      all3 |= 4;
        // start at first family in cert. NOTE order must be v4 then v6, per RFC3779
      rpAddrFamp = &extp->extnValue.ipAddressBlock.iPAddressFamilyA;
      read_casn(&rpAddrFamp->addressFamily, cfam);
      for (ripAddrFamp = &rp->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks.
        rOAIPAddressFamily; 
        iRes == cTRUE && ripAddrFamp; 
        ripAddrFamp = (struct ROAIPAddressFamily *)next_of(&ripAddrFamp->self))
        {  // find that family in cert
        read_casn(&ripAddrFamp->addressFamily, rfam);
        while (rpAddrFamp && memcmp(cfam, rfam, 2) != 0)
          {
          if (!(rpAddrFamp = (struct IPAddressFamilyA *)next_of(&rpAddrFamp->self))) 
            iRes = ERR_SCM_INVALIPB;
          else  read_casn(&rpAddrFamp->addressFamily, cfam);
          }
        if (iRes == 0)
          {  // set up initial entry in cert
          rpAddrRangep = &rpAddrFamp->ipAddressChoice.addressesOrRanges.iPAddressOrRangeA;
          if ((sta=setup_cert_minmax(rpAddrRangep, cmin, cmax, cfam[1])) < 0) iRes = sta;
               // go through all ip addresses in ROA
          for (ripAddrp = &ripAddrFamp->addresses.iPAddress; ripAddrp && iRes == 0; 
            ripAddrp = (struct IPAddress *)next_of(ripAddrp))
            {   // set up the limits
	      if ((sta=setup_roa_minmax(ripAddrp, rmin, rmax, rfam[1])) < 0) iRes = sta;
              // go through cert addresses until a high enough one is found
              // i.e. skip cert addresses whose max is below roa's min
            while (iRes == 0 && rpAddrRangep && 
              memcmp(&cmax[2], &rmin[2], sizeof(rmin) - 2) <= 0)
              {
              if (!(rpAddrRangep = (struct IPAddressOrRangeA *)next_of(&rpAddrRangep->self)) ||
                  setup_cert_minmax(rpAddrRangep, cmin, cmax, cfam[1]) < 0) iRes = ERR_SCM_INVALIPB;
              }
            if (rpAddrRangep && iRes == 0)  
              {  // now at cert values at or beyond roa
                  // if roa min is below cert min OR roa max beyond cert max, bail out
              if ((ii = memcmp(&rmin[2], &cmin[2], sizeof(cmin) - 2)) < 0 ||
                  (ij = memcmp(&rmax[2], &cmax[2], sizeof(cmin) - 2)) > 0) break;
              }
            }
          if (ripAddrp) iRes = ERR_SCM_INVALIPB;
          }
        }     
      }
    }
  if (all3 != 7) iRes = ERR_SCM_INVALIPB;
  if (iRes == 0)  // check the signature
    {
    iRes = check_sig(rp, &cert);
    }
  delete_casn(&cert.self);
  return iRes;
  }
