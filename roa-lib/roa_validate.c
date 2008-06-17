/*
  $Id: roa_validate.c 506 2008-06-03 21:20:05Z csmall $
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
  cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_KEY_COMPONENTS, &rsakey, 
    sizeof(CRYPT_PKCINFO_RSA));
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

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, int alg)
  { // used for manifests      alg = 1 for SHA-1; alg = 2 for SHA2
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  memset(hash, 0, 40);
  cryptInit();
  if (alg == 2) cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  else if (alg == 1) cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA);
  else return ERR_SCM_BADALG;
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static int getTime(struct CertificateValidityDate *cvdp, ulong *datep)
  {
  int ansr;
  if (size_casn(&cvdp->utcTime) == 0) ansr = read_casn_time(&cvdp->generalTime, datep);
  else ansr = read_casn_time(&cvdp->utcTime, datep);
  return ansr;
  } 


static int check_cert(struct Certificate *certp)
  {
  int tmp;
  ulong lo, hi;
  struct CertificateToBeSigned *certtbsp = &certp->toBeSigned;

  if (read_casn_num(&certp->toBeSigned.version.self, (long*)&tmp) < 0 ||
    tmp != 2) return ERR_SCM_BADVERS;
  if (diff_casn(&certtbsp->signature.algorithm, &certp->algorithm.algorithm)) 
    return ERR_SCM_BADALG;
  if (getTime(&certtbsp->validity.notBefore, &lo) < 0 ||
    getTime(&certtbsp->validity.notAfter, &hi) < 0 || lo >= hi)
    return ERR_SCM_BADDATES;
  struct casn *spkeyp = &certtbsp->subjectPublicKeyInfo.subjectPublicKey;
  uchar *pubkey;
  tmp = readvsize_casn(spkeyp, &pubkey);
  uchar khash[22];
  tmp = gen_hash(&pubkey[1], tmp - 1, khash, 1);
  free(pubkey);
  int err = 1;  // require SKI
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&certtbsp->extensions.self, 0);
    extp; extp = (struct Extension *)next_of(&extp->self))
    {
    if (!diff_objid(&extp->extnID, id_basicConstraints) &&
        size_casn(&extp->extnValue.basicConstraints.cA) > 0) return ERR_SCM_NOTEE; 
    if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier))
      {
      uchar *ski;
      int ski_lth = readvsize_casn(&extp->extnValue.subjectKeyIdentifier, &ski);
      if (ski_lth != tmp || memcmp(khash, ski, ski_lth)) err = ERR_SCM_INVALSKI;
      free(ski);
      if (err < 0) return err;
      err = 0;
      }
    }
  if (err == 1) return ERR_SCM_NOSKI;  // no SKI
  return 0;
  }

static int check_fileAndHash(struct FileAndHash *fahp, int ffd)
  {
  uchar *contentsp;
  int err = 0,
      hash_lth, bit_lth, name_lth = lseek(ffd, 0, SEEK_END);

  lseek(ffd, 0, SEEK_SET);
  contentsp = (uchar *)calloc(1, name_lth + 2);
  if (read(ffd, contentsp, name_lth + 2) != name_lth) err = ERR_SCM_BADFILE;
  else if ((hash_lth = gen_hash(contentsp, name_lth, contentsp, 2)) < 0) 
    err = ERR_SCM_BADHASH;
  else
    {
    bit_lth = vsize_casn(&fahp->hash);
    uchar *hashp = (uchar *)calloc(1, bit_lth);
    read_casn(&fahp->hash, hashp);
    if (hash_lth != bit_lth - 1 || memcmp(&hashp[1], contentsp, hash_lth)) 
      err = ERR_SCM_BADHASH;
    free(hashp);
    close(ffd);
    }
  free(contentsp);
  return err;
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
  if (size_casn(ripAddrp) > fam) return ERR_SCM_INVALIPL;
  encode_casn(ripAddrp, rmin);
  encode_casn(ripAddrp, rmax);
  fill_max(rmax);
  rmin[2] = 0;
  rmax[2] = 0;
  return 0;
  }

static int test_maxLength(struct ROAIPAddress *roaAddrp)
  {
  if (size_casn(&roaAddrp->maxLength) == 0) return 0;
  long maxLength = 0;
  int lth = vsize_casn(&roaAddrp->address);
  uchar *addr = (uchar *)calloc(1, lth);
  read_casn(&roaAddrp->address, addr);
  free(addr);
  lth = ((lth - 1) * 8) + ((8 - addr[0]) & 7);
  read_casn_num(&roaAddrp->maxLength, &maxLength);
  if (lth > maxLength) return ERR_SCM_INVALIPL;
  return 0;
  }

static int validateIPContents(struct ROAIPAddrBlocks *ipAddrBlockp)
  {
  // check that addressFamily is IPv4 OR IPv6
  // check that the addressPrefixes are valid IP addresses OR valid ranges
  uchar rmin[MINMAXBUFSIZE], rmax[MINMAXBUFSIZE], oldmax[MINMAXBUFSIZE], rfam[8];
  struct ROAIPAddress *roaAddrp;
  struct ROAIPAddressFamily *roaipfamp;
  int i = 0, err = 0;

  for (roaipfamp = &ipAddrBlockp->rOAIPAddressFamily; roaipfamp; 
    roaipfamp = (struct ROAIPAddressFamily *)next_of(&roaipfamp->self))
    {
    if (read_casn(&roaipfamp->addressFamily, rfam) < 0 ||
	rfam[0] != 0 || (rfam[1] != 1 && rfam[1] != 2)) return ERR_SCM_INVALFAM;
    i = rfam[1]; 
    memset(oldmax, 0, sizeof(oldmax));
    for (roaAddrp = &roaipfamp->addresses.rOAIPAddress; roaAddrp; 
      roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
      {
      if ((err = test_maxLength(roaAddrp)) < 0 ||
        (err = setup_roa_minmax(&roaAddrp->address, rmin, rmax, i)) < 0) return err;
      if (memcmp(&rmin[3], &oldmax[3], sizeof(rmin) - 3) < 0 || 
	memcmp(&rmax[3], &rmin[3],   sizeof(rmin) - 3) < 0) return ERR_SCM_INVALIPB;
      }
    }
  return 0;
  }

static int cmsValidate(struct ROA *rp)
    {  // validates general CMS things common to ROAs and manifests
  // check that roa->content->version == 3
  if (diff_casn_num(&rp->content.signedData.version.self, 3) != 0) return ERR_SCM_BADVERS;

  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (num_items(&rp->content.signedData.digestAlgorithms.self) != 1 ||
    diff_objid(&rp->content.signedData.digestAlgorithms.digestAlgorithmIdentifier.
      algorithm, id_sha256)) return ERR_SCM_BADDA;
  int certs;
  if ((certs = num_items(&rp->content.signedData.certificates.self)) > 1) 
    return ERR_SCM_BADNUMCERTS;
  if (certs)
    {
    int tmp;
    struct Certificate *certp = (struct Certificate *)member_casn(
      &rp->content.signedData.certificates.self, 0);
    if ((certs = check_cert(certp)) < 0) return certs;
    if ((tmp = check_sig(rp, certp)) != 0) return tmp;
    }
  // check that roa->content->crls == NULL
  if (size_casn(&rp->content.signedData.crls.self) > 0 ||
     num_items(&rp->content.signedData.signerInfos.self) != 1 ||
     diff_casn_num(&rp->content.signedData.signerInfos.signerInfo.version.self, 3) != 0) 
    return ERR_SCM_BADVERS;

  // check that roa->content->signerInfoStruct->digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (diff_objid(&rp->content.signedData.signerInfos.signerInfo.digestAlgorithm.
     algorithm, id_sha256)) return ERR_SCM_BADCRL;

  if(size_casn(&rp->content.signedData.signerInfos.signerInfo.signedAttrs.self) != 0 ||
     size_casn(&rp->content.signedData.signerInfos.signerInfo.unsignedAttrs.self) != 0) 
    return ERR_SCM_BADATTR;

  // check that roa->content->signerInfoStruct->signatureAlgorithm == 
  //   RSAEncryption (= OID 1.2.240.113549.1.1.1)
  if(diff_objid(&rp->content.signedData.signerInfos.signerInfo.signatureAlgorithm.
    algorithm, id_rsadsi_rsaEncryption)) return ERR_SCM_INVALSIG;

  // check that the subject key identifier has proper length 
  if (vsize_casn(&rp->content.signedData.signerInfos.signerInfo.sid.subjectKeyIdentifier) != 20)
    return ERR_SCM_INVALSKI;
  return 0;
  }

void free_badfiles(struct badfile **badfilespp)
  {  // for rsync_aur or anyone else who calls manifestValidate2
  struct badfile **bpp;
  for (bpp = badfilespp; *bpp; bpp++)
    {
    free((*bpp)->fname);
    free(*bpp);
    }
  free(badfilespp);
  }

int manifestValidate2(struct ROA *rp, char *dirp, struct badfile ***badfilesppp)
  {
  struct FileAndHash *fahp;
  struct Manifest *manp;
  struct Certificate *certp;
  struct badfile **badfilespp = (struct badfile **)0;
  char *fname, *path;
  int numbadfiles = 0, dir_lth, err = 0, ffd, tmp; 
       // do general checks including signature if cert is present
  if ((err = cmsValidate(rp)) < 0) return err;
     // certificate checks
  if (num_items(&rp->content.signedData.certificates.self) != 1) return ERR_SCM_BADNUMCERTS;
  certp = (struct Certificate *)member_casn(&rp->content.signedData.certificates.self, 0);
  if ((tmp = check_cert(certp)) < 0) return tmp;
      // other specific manifest checks
  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType, 
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
  manp = &rp->content.signedData.encapContentInfo.eContent.manifest;
  ulong mlo, mhi;
  if (read_casn_time(&manp->thisUpdate, &mlo) <= 0 ||
      read_casn_time(&manp->nextUpdate, &mhi) <= 0 ||
      mlo >= mhi) return ERR_SCM_BADDATES;
     // signature OK?
      // all checks done.  Get to the details
  if (dirp && *dirp) 
    {
    dir_lth = strlen(dirp) + 1;
    if (dirp[dir_lth - 2] == '/') dir_lth--;
    }
  else dir_lth = 0;
  path = (char *)calloc(1, dir_lth + 1);
  for (fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, 0); fahp; 
    fahp = (struct FileAndHash *)next_of(&fahp->self))
    {
    int name_lth = vsize_casn(&fahp->file);
    fname = (char *)calloc(1, name_lth + 8);
    read_casn(&fahp->file, (uchar *)fname);
    path = (char *)realloc(path, dir_lth + name_lth + 4);
    if (dir_lth) strcat(strncpy(path, dirp, dir_lth), "/");
    strcat(path, fname);
    tmp = 0;
    if ((ffd = open(path, O_RDONLY)) < 0) tmp = ERR_SCM_COFILE;
    else tmp = check_fileAndHash(fahp, ffd);
    if (tmp < 0)  // add the file to the list 
      {
      if (numbadfiles == 0) 
	badfilespp = (struct badfile **)calloc(2, sizeof(struct badfile *));
      else badfilespp = (struct badfile **)realloc(badfilespp, ((numbadfiles + 1) * 
        sizeof(struct badfile *)));
      struct badfile *badfilep = (struct badfile *)calloc(1, sizeof(struct badfile));
      badfilespp[numbadfiles++] = badfilep;
      badfilep->fname = fname;
      badfilep->err = tmp;
      if (!err) err = tmp;
      }
    else free(fname);
    }
  free(path);
  *badfilesppp = badfilespp;
  return err;
  }

int roaValidate(struct ROA *rp)
{
  // Make sure that the ROA meets the provisions outlined in 
  // Kent/Kong ROA IETF draft
  int iRes = 0;
  long iAS_ID = 0;

  /////////////////////////////////////////////////////////////
  // Validate ROA constants
  /////////////////////////////////////////////////////////////
  if((iRes = cmsValidate(rp)) < 0) return iRes;

  // check that eContentType is routeOriginAttestation (= OID 1.2.240.113549.1.9.16.1.24)
  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType,
    id_routeOriginAttestation)) return ERR_SCM_BADCT;

  // check that the asID is  a positive nonzero integer
  if (read_casn_num(&rp->content.signedData.signerInfos.signerInfo.version.self, &iAS_ID) < 0 ||
      iAS_ID <= 0) return ERR_SCM_INVALASID;
  // check the contents
  if ((iRes = validateIPContents(&rp->content.signedData.encapContentInfo.eContent.roa.
     ipAddrBlocks)) < 0) return iRes;
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
  struct ROAIPAddress *roaAddrp;
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
          for (roaAddrp = &ripAddrFamp->addresses.rOAIPAddress; roaAddrp && iRes == 0; 
            roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
            {   // set up the limits
	    if ((sta = setup_roa_minmax(&roaAddrp->address, rmin, rmax, rfam[1])) < 0) 
                iRes = sta;
              // go through cert addresses until a high enough one is found
              // i.e. skip cert addresses whose max is below roa's min
            while (iRes == 0 && rpAddrRangep && 
              memcmp(&cmax[2], &rmin[2], sizeof(rmin) - 2) <= 0)
              {
              if (!(rpAddrRangep = 
                  (struct IPAddressOrRangeA *)next_of(&rpAddrRangep->self)) ||
                  setup_cert_minmax(rpAddrRangep, cmin, cmax, cfam[1]) < 0) 
                  iRes = ERR_SCM_INVALIPB;
              }
            if (rpAddrRangep && iRes == 0)  
              {  // now at cert values at or beyond roa
                  // if roa min is below cert min OR roa max beyond cert max, bail out
              if ((ii = memcmp(&rmin[2], &cmin[2], sizeof(cmin) - 2)) < 0 ||
                  (ij = memcmp(&rmax[2], &cmax[2], sizeof(cmin) - 2)) > 0) break;
              }
            }
          if (roaAddrp) iRes = ERR_SCM_INVALIPB;
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
