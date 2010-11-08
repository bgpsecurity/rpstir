/*
  $Id: roa_validate.c 506 2008-06-03 21:20:05Z csmall $
*/

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner, Joshua Gruenspecht
 *
 * ***** END LICENSE BLOCK ***** */

#include <assert.h>

#include "roa_utils.h"
#include "cryptlib.h"

/*
  This file contains the functions that semantically validate the ROA.
  Any and all syntactic validation against existing structures is assumed
  to have been performed at the translation step (see roa_serialize.c).
*/

#define MINMAXBUFSIZE 20

static int CryptInitState;

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
		    CRYPT_ALGO_TYPE alg)
{ // used for manifests      alg = 1 for SHA-1; alg = 2 for SHA2
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int   ansr = -1;

  if ( alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2 )
    return ERR_SCM_BADALG;
  memset(hash, 0, sizeof(hash));
  if ( !CryptInitState )
    {
      cryptInit();
      CryptInitState = 1;
    }
  cryptCreateContext(&hashContext, CRYPT_UNUSED, alg);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  //  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
}

int check_sig(struct ROA *rp, struct Certificate *certp)
  {
  CRYPT_CONTEXT pubkeyContext, hashContext;
  CRYPT_PKCINFO_RSA rsakey;
  // CRYPT_KEYSET cryptKeyset;
  struct RSAPubKey rsapubkey;
  int bsize, ret, sidsize;
  uchar *c, *buf, hash[40], sid[40];

  // get SID and generate the sha-1 hash
  // (needed for cryptlib; see below)
  memset(sid, 0, 40);
  bsize = size_casn(&certp->toBeSigned.subjectPublicKeyInfo.self);
  if (bsize < 0) return ERR_SCM_INVALSIG;;
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&certp->toBeSigned.subjectPublicKeyInfo.self, buf);
  sidsize = gen_hash(buf, bsize, sid, CRYPT_ALGO_SHA);
  free(buf);

  // generate the sha256 hash of the signed attributes. We don't call
  // gen_hash because we need the hashContext for later use (below).
  struct SignerInfo *sigInfop = (struct SignerInfo *)
      member_casn(&rp->content.signedData.signerInfos.self, 0);
  memset(hash, 0, 40);
  bsize = size_casn(&sigInfop->signedAttrs.self);
  if (bsize < 0) return ERR_SCM_INVALSIG;;
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&sigInfop->signedAttrs.self, buf);
  *buf = ASN_SET;

  // (re)init the crypt library
  if (!CryptInitState)
    {
    cryptInit();
    CryptInitState = 1;
    }
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, buf, bsize);
  cryptEncrypt(hashContext, buf, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ret);
  assert(ret == 32);		/* size of hash; should never fail */
  free(buf);

  // get the public key from the certificate and decode it into an RSAPubKey
  readvsize_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey, &c);
  RSAPubKey(&rsapubkey, 0);
  decode_casn(&rsapubkey.self, &c[1]);  // skip 1st byte (tag?) in BIT STRING
  free(c);

  // set up the key by reading the modulus and exponent
  cryptCreateContext(&pubkeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
  cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
  cryptInitComponents(&rsakey, CRYPT_KEYTYPE_PUBLIC);

  // read the modulus from rsapubkey
  bsize = readvsize_casn(&rsapubkey.modulus, &buf);
  c = buf;
  // if the first byte is a zero, skip it
  if (!*buf)
    {
    c++;
    bsize--;
    }
  cryptSetComponent((&rsakey)->n, c, bsize * 8);
  free(buf);

  // read the exponent from the rsapubkey
  bsize = readvsize_casn(&rsapubkey.exponent, &buf);
  cryptSetComponent((&rsakey)->e, buf, bsize * 8);
  free(buf);

  // set the modulus and exponent on the key
  cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_KEY_COMPONENTS, &rsakey,
			  sizeof(CRYPT_PKCINFO_RSA));
  // all done with this now, free the storage
  cryptDestroyComponents(&rsakey);

  // make the structure cryptlib likes.
  // we discovered through detective work that cryptlib wants the
  // signature's SID field to be the sha-1 hash of the SID.
  struct SignerInfo sigInfo;
  SignerInfo(&sigInfo, (ushort)0); /* init sigInfo */
  copy_casn(&sigInfo.version.self, &sigInfop->version.self); /* copy over */
  copy_casn(&sigInfo.sid.self, &sigInfop->sid.self); /* copy over */
  write_casn(&sigInfo.sid.subjectKeyIdentifier, sid, sidsize); /* sid * hash */

  // copy over digest algorithm, signature algorithm, signature
  copy_casn(&sigInfo.digestAlgorithm.self, &sigInfop->digestAlgorithm.self);
  copy_casn(&sigInfo.signatureAlgorithm.self, &sigInfop->signatureAlgorithm.self);
  copy_casn(&sigInfo.signature, &sigInfop->signature);

  // now encode as asn1, and check the signature
  bsize = size_casn(&sigInfo.self);
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&sigInfo.self, buf);
  ret = cryptCheckSignature(buf, bsize, pubkeyContext, hashContext);
  free(buf);

  // all done, clean up
  cryptDestroyContext(pubkeyContext);
  cryptDestroyContext(hashContext);
//  cryptEnd();
  delete_casn(&rsapubkey.self);
  delete_casn(&sigInfo.self);

  // if the value returned from crypt above != 0, it's invalid
  return (ret != 0) ? ERR_SCM_INVALSIG : 0;
  }

static void fill_max(uchar *max)
  {
  max[max[1] + 1] |= ((1 << max[2]) - 1);
  }

static int getTime(struct CertificateValidityDate *cvdp, ulong *datep)
  {
  int ansr;
  if (size_casn(&cvdp->utcTime) == 0)
      ansr = read_casn_time(&cvdp->generalTime, datep);
  else
      ansr = read_casn_time(&cvdp->utcTime, datep);
  return ansr;
  }


static int check_cert(struct Certificate *certp, int isEE)
  {
  int tmp;
  ulong lo, hi;
  struct CertificateToBeSigned *certtbsp = &certp->toBeSigned;

  if (read_casn_num(&certp->toBeSigned.version.self, (long*)&tmp) < 0 ||
    tmp != 2) return ERR_SCM_BADVERS;
  if (diff_casn(&certtbsp->signature.algorithm, &certp->algorithm.algorithm))
    return ERR_SCM_BADALG;
  if (getTime(&certtbsp->validity.notBefore, &lo) < 0 ||
    getTime(&certtbsp->validity.notAfter, &hi) < 0 || lo > hi)
    return ERR_SCM_BADDATES;
  struct casn *spkeyp = &certtbsp->subjectPublicKeyInfo.subjectPublicKey;
  uchar *pubkey;
  tmp = readvsize_casn(spkeyp, &pubkey);
  uchar khash[22];
  tmp = gen_hash(&pubkey[1], tmp - 1, khash, CRYPT_ALGO_SHA);
  free(pubkey);
  int err = 1;  // require SKI
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&certtbsp->extensions.self, 0);
    extp; extp = (struct Extension *)next_of(&extp->self))
    {
    if (isEE && !diff_objid(&extp->extnID, id_basicConstraints) &&
	size_casn(&extp->extnValue.basicConstraints.cA) > 0)
	return ERR_SCM_NOTEE;
    if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier))
      {
      uchar *ski;
      int ski_lth = readvsize_casn(&extp->extnValue.subjectKeyIdentifier, &ski);
#ifndef ANYSKI
      if (ski_lth != tmp || memcmp(khash, ski, ski_lth)) err = ERR_SCM_INVALSKI;
#endif
      free(ski);
      if (err < 0) return err;
      err = 0;
      }
    }
  if (err == 1) return ERR_SCM_NOSKI;  // no SKI
  return 0;
  }

/*
  If the hash is given as "inhash", check to see that the hash inside the
  FileAndHash struct is the same. If the hash is not given in "inhash" then
  compute the hash, check it against the hash in FileAndHash, and then store
  the hash (if the comparison succeeded) in "inhash". "inhashlen" is the number
  of bytes actually used in "inhash" (which is a binary array, not a string),
  and "inhashtotlen" is the total space available in that array.

  On success this function returns the length, in bytes, of the hash. On
  failure it returns a negative error code.
*/

int check_fileAndHash(struct FileAndHash *fahp, int ffd, uchar *inhash,
		      int inhashlen, int inhashtotlen)
{
  uchar *contentsp;
  int err = 0;
  int hash_lth;
  int bit_lth;
  int name_lth = lseek(ffd, 0, SEEK_END);

  lseek(ffd, 0, SEEK_SET);
  contentsp = (uchar *)calloc(1, name_lth + 2);
  if ( read(ffd, contentsp, name_lth + 2) != name_lth )
    {
      free(contentsp);
      return(ERR_SCM_BADFILE);
    }
  if ( inhash != NULL && inhashlen > 0 && inhashlen <= (name_lth+2) )
    {
      memcpy(contentsp, inhash, inhashlen);
      hash_lth = inhashlen;
    }
  else
    {
      hash_lth = gen_hash(contentsp, name_lth, contentsp, CRYPT_ALGO_SHA2);
      if ( hash_lth < 0 )
	{
	  free(contentsp);
	  return(ERR_SCM_BADHASH);
	}
    }
  bit_lth = vsize_casn(&fahp->hash);
  uchar *hashp = (uchar *)calloc(1, bit_lth);
  read_casn(&fahp->hash, hashp);
  if ( hash_lth != (bit_lth - 1) ||
       memcmp(&hashp[1], contentsp, hash_lth) != 0 )
    err = ERR_SCM_BADHASH;
  free(hashp);
  if ( inhash != NULL && inhashtotlen >= hash_lth && inhashlen == 0 && err == 0 )
    memcpy(inhash, contentsp, hash_lth);
  free(contentsp);
  return err == 0 ? hash_lth : err;
}

static struct Attribute *find_attr(struct SignedAttributes *attrsp, char *oidp)
  {
  struct Attribute *attrp, *ch_attrp = NULL;
  int num = 0;
  for (attrp = (struct Attribute *)member_casn(&attrsp->self, num);
    attrp; attrp = (struct Attribute *)next_of(&attrp->self), num++)
    {
    if (!diff_objid(&attrp->attrType, oidp))
      {
      if (ch_attrp) return NULL;
      ch_attrp = attrp;
      }
    }
    // make sure there is one and only one value there
  if (num_items(&ch_attrp->attrValues.self) != 1) return NULL;
  return ch_attrp;
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
  /* Compute the length of the IP prefix, noting that the ASN.1
     encoding of a bit string uses the first byte to specify the
     number of unused bits at the end. */
  int addrLength = ((lth - 1) * 8) - addr[0];
  free(addr);
  read_casn_num(&roaAddrp->maxLength, &maxLength);
  if (addrLength > maxLength) return ERR_SCM_INVALIPL;
  return 0;
  }

static int validateIPContents(struct ROAIPAddrBlocks *ipAddrBlockp)
  {
  // check that addressFamily is IPv4 OR IPv6
  // check that the addressPrefixes are valid IP addresses OR valid ranges
  uchar rmin[MINMAXBUFSIZE], rmax[MINMAXBUFSIZE], rfam[8];
  struct ROAIPAddress *roaAddrp;
  struct ROAIPAddressFamily *roaipfamp;
  int i, err = 0, num = 0;

  if ((i = num_items(&ipAddrBlockp->self)) == 0 || i > 2)
    return ERR_SCM_INVALFAM;
  i = 0;
  for (roaipfamp = (struct ROAIPAddressFamily *)member_casn(
    &ipAddrBlockp->self, 0); roaipfamp;
    roaipfamp = (struct ROAIPAddressFamily *)next_of(&roaipfamp->self),
    num++)
    {
    if (read_casn(&roaipfamp->addressFamily, rfam) < 0 ||
	rfam[0] != 0 || (rfam[1] != 1 && rfam[1] != 2)) return ERR_SCM_INVALFAM;
    i = rfam[1];
    if (num == 1 && i == 1) return ERR_SCM_INVALFAM; 
    for (roaAddrp = &roaipfamp->addresses.rOAIPAddress; roaAddrp;
      roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
      {
      if ((err = test_maxLength(roaAddrp)) < 0 ||
	  (err = setup_roa_minmax(&roaAddrp->address, rmin, rmax, i)) < 0) 
	  return err;
      if (memcmp(&rmax[3], &rmin[3],   sizeof(rmin) - 3) < 0) 
	  return ERR_SCM_INVALIPB;
      }
    }
  return 0;
  }

static int cmsValidate(struct ROA *rp)
  {
  // validates general CMS things common to ROAs and manifests

  int num_certs, ret = 0, tbs_lth;
  struct SignerInfo *sigInfop;
  uchar digestbuf[40], hashbuf[40];
  uchar *tbsp;

  // check that roa->content->version == 3
  if (diff_casn_num(&rp->content.signedData.version.self, 3) != 0)
	return ERR_SCM_BADVERS;
  int notRTA = diff_objid(&rp->content.signedData.encapContentInfo.
    eContentType, id_ct_RPKITrustAnchor);

  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (num_items(&rp->content.signedData.digestAlgorithms.self) != 1 ||
	diff_objid(&rp->content.signedData.digestAlgorithms.
      cMSAlgorithmIdentifier.algorithm, id_sha256))
	return ERR_SCM_BADDA;

  if ((num_certs = num_items(&rp->content.signedData.certificates.self)) > 1)
	return ERR_SCM_BADNUMCERTS;

  if (num_items(&rp->content.signedData.signerInfos.self) != 1)
	return ERR_SCM_BADSIGINFO;

  sigInfop = (struct SignerInfo *)member_casn(&rp->content.signedData.
    signerInfos.self, 0);
  memset(digestbuf, 0, 40);

  if (diff_casn_num(&sigInfop->version.self, 3) ||
     !size_casn(&sigInfop->sid.subjectKeyIdentifier) ||
     diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256))
     return ERR_SCM_BADSIGINFO;

  struct Attribute *attrp;
  // make sure there is content
  attrp = find_attr(&sigInfop->signedAttrs, id_contentTypeAttr);
  if (!attrp ||
  // make sure it is the same as in EncapsulatedContentInfo
      diff_casn(&attrp->attrValues.array.contentType, 
      &rp->content.signedData.encapContentInfo.eContentType) ||
  // make sure there is a message digest
     !(attrp = find_attr(&sigInfop->signedAttrs, id_messageDigestAttr)) ||
  // make sure the message digest is 32 bytes long and we can get it
     vsize_casn(&attrp->attrValues.array.messageDigest) != 32 ||
     read_casn(&attrp->attrValues.array.messageDigest, digestbuf) != 32)
     return ERR_SCM_BADSIGINFO;

  // make sure there is a signing time
  attrp = find_attr(&sigInfop->signedAttrs, id_signingTimeAttr);
  if (!attrp && notRTA) return ERR_SCM_BADSIGINFO;
     // make sure it is the right format      
  if (attrp)
    {
    uchar loctime[30];
    int usize, gsize;
    if ((usize = vsize_casn(&attrp->attrValues.array.signingTime.utcTime)) > 
       15 ||
       (gsize = vsize_casn(&attrp->attrValues.array.signingTime.
          generalizedTime)) > 17) return ERR_SCM_BADSIGINFO;
    if (usize > 0) 
      {
      read_casn(&attrp->attrValues.array.signingTime.utcTime, loctime);
      if (loctime[0] <= '7' && loctime[0] >= '5') return ERR_SCM_BADSIGINFO;
      }
    else
      {
      read_casn(&attrp->attrValues.array.signingTime.generalizedTime, 
        loctime);
      if (strncmp((char *)loctime, "2050", 4) < 0) return ERR_SCM_BADSIGINFO;
      }
    }
  // check the hash
  memset(hashbuf, 0, 40);
  // read the content
  tbs_lth = readvsize_casn(&rp->content.signedData.encapContentInfo.eContent.
    self, &tbsp);

  // hash it, make sure it's the right length and it matches the digest
  if (gen_hash(tbsp, tbs_lth, hashbuf, CRYPT_ALGO_SHA2) != 32 ||
	memcmp(digestbuf, hashbuf, 32) != 0) 
	ret =ERR_SCM_BADHASH;
  free(tbsp);			// done with the content now

  // if the hash didn't match, bail now
  if (ret != 0)
	return ret;

  // if there is a cert, check it
  if (num_certs > 0) {
	struct Certificate *certp = (struct Certificate *)
	member_casn(&rp->content.signedData.certificates.self, 0);
	if ((ret = check_cert(certp, 1)) < 0)
	  return ret;
	if ((ret = check_sig(rp, certp)) != 0)
	  return ret;
    // check that the cert's SKI matches that in SignerInfo
    struct Extension *extp;
    for (extp = (struct Extension *)
	member_casn(&certp->toBeSigned.extensions.self, 0); extp &&
	diff_objid(&extp->extnID, id_subjectKeyIdentifier); 
	extp = (struct Extension *)next_of(&extp->self));
    if (!extp) return ERR_SCM_BADSIGINFO;
    if (diff_casn(&extp->extnValue.subjectKeyIdentifier,
	&sigInfop->sid.subjectKeyIdentifier)) return ERR_SCM_BADSIGINFO;
    
  }

  // check that roa->content->crls == NULL
  if (size_casn(&rp->content.signedData.crls.self) > 0 ||
	num_items(&rp->content.signedData.signerInfos.self) != 1 ||
	diff_casn_num(&rp->content.signedData.signerInfos.signerInfo.version.
        self, 3) != 0)
	return ERR_SCM_BADVERS;

  // check that roa->content->signerInfo.digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (diff_objid(&rp->content.signedData.signerInfos.signerInfo.
    digestAlgorithm.algorithm, id_sha256))
	return ERR_SCM_BADDA;

  if (size_casn(&rp->content.signedData.signerInfos.signerInfo.unsignedAttrs.
    self) != 0)
	return ERR_SCM_BADATTR;

  // check that roa->content->signerInfoStruct->signatureAlgorithm ==
  //   RSAEncryption (= OID 1.2.240.113549.1.1.1)
  if (diff_objid(&rp->content.signedData.signerInfos.signerInfo.
    signatureAlgorithm.algorithm, id_rsadsi_rsaEncryption))
	return ERR_SCM_INVALSIG;

  // check that the subject key identifier has proper length
  if (vsize_casn(&rp->content.signedData.signerInfos.signerInfo.sid.
    subjectKeyIdentifier) != 20)
	return ERR_SCM_INVALSKI;

  // everything checked out
  return 0;
  }
/*
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
  struct badfile **badfilespp = (struct badfile **)0;
  char *fname, *path;
  int numbadfiles = 0, dir_lth, err = 0, ffd, tmp;
       // do general checks including signature if cert is present
  if ((err = cmsValidate(rp)) < 0) return err;
     // certificate check
  if (num_items(&rp->content.signedData.certificates.self) != 1) 
    return ERR_SCM_BADNUMCERTS;
      // other specific manifest checks
  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType,
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
  manp = &rp->content.signedData.encapContentInfo.eContent.manifest;
  ulong mlo, mhi;
  if (read_casn_time(&manp->thisUpdate, &mlo) <= 0 ||
      read_casn_time(&manp->nextUpdate, &mhi) <= 0 ||
      mlo >= mhi) return ERR_SCM_BADDATES;
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
      else badfilespp = (struct badfile **)realloc(badfilespp, ((numbadfiles + 2) *
        sizeof(struct badfile *)));
      struct badfile *badfilep = (struct badfile *)calloc(1, sizeof(struct badfile));
      badfilespp[numbadfiles++] = badfilep;
      badfilespp[numbadfiles] = (struct badfile *)0;
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
*/

int rtaValidate(struct ROA *rtap)
  {
  int iRes = cmsValidate(rtap);
  if (iRes < 0) return iRes;

  // check eContentType  
  if (diff_objid(&rtap->content.signedData.encapContentInfo.eContentType,
    id_ct_RPKITrustAnchor)) return ERR_SCM_BADCT;
  if ((iRes = check_cert(&rtap->content.signedData.encapContentInfo.eContent.
    trustAnchor, 0)) < 0) return iRes; 
  return 0;
  }

int manifestValidate(struct ROA *manp)
  {
  int iRes = cmsValidate(manp);
  if (iRes < 0) return iRes;

  // check that eContentType is id-roa-pki-manifest(= OID 
  //    1.2.240.113549.1.9.16.1.26)
  if (diff_objid(&manp->content.signedData.encapContentInfo.eContentType,
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
  // check that the version is right
  struct casn *casnp = &manp->content.signedData.encapContentInfo.
    eContent.manifest.version.self;
  long val;
  if (size_casn(casnp) > 0 && (read_casn_num(casnp, &val) > 1 ||
      val > 0)) return ERR_SCM_INVALVER;
  return 0;
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

  // check that eContentType is routeOriginAttestation (= 
  //    OID 1.2.240.113549.1.9.16.1.24)
  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType,
    id_routeOriginAttestation)) return ERR_SCM_BADCT;

  // check that the version is right
  struct casn *casnp = &rp->content.signedData.encapContentInfo.eContent.
    roa.version.self;
  long val;
  if (size_casn(casnp) > 0 && read_casn_num(casnp, &val) > 1 &&
      val > 0) return ERR_SCM_INVALVER;
  // check that the asID is  a positive nonzero integer
  if (read_casn_num(&rp->content.signedData.signerInfos.signerInfo.version.
    self, &iAS_ID) < 0 ||
      iAS_ID <= 0) return ERR_SCM_INVALASID;
  // check the contents
  if ((iRes = validateIPContents(&rp->content.signedData.encapContentInfo.
     eContent.roa.  ipAddrBlocks)) < 0) return iRes;
  return 0;
  }

#define HAS_EXTN_SKI 0x01
#define HAS_EXTN_ASN 0x02
#define HAS_EXTN_IPADDR 0x04

int roaValidate2(struct ROA *rp)
{
  int iRes;
  int sta;
  long ii, ij;
  struct Extension *extp;
  char *oidp;
  uchar cmin[MINMAXBUFSIZE], cmax[MINMAXBUFSIZE], rmin[MINMAXBUFSIZE], 
    rmax[MINMAXBUFSIZE];
  uchar rfam[8], cfam[8];
  int all_extns = 0;

  // roaValidate() is an independent function; the caller must call it
  // if the caller wants semantic validation
  //  if (roaValidate(r) == FALSE) return FALSE;
  struct Certificate *cert = (struct Certificate *) 
      member_casn(&rp->content.signedData.certificates.self, 0);

  //
 // if (certificate exists in roa)
  // -  ignore it
  // -  Or check the certificate against x (optional)

  /////////////////////////////////////////////////////////////////
  // We get to assume cert validity up the chain, because by virtue
  //  of having been extracted, it is reputable
  /////////////////////////////////////////////////////////////////
  iRes = 0;
  for (extp = (struct Extension *)&cert->toBeSigned.extensions.extension;
    extp && iRes == 0;
    extp = (struct Extension *)next_of(&extp->self))
    {
    readvsize_objid(&extp->extnID, &oidp);
       // if it's the SKID extension
    if (!memcmp(oidp, id_subjectKeyIdentifier, strlen(oidp)))
      {
      all_extns |= HAS_EXTN_SKI;
      // Check that roa->envelope->SKI = cert->SKI
      if (diff_casn(&rp->content.signedData.signerInfos.signerInfo.sid.
        subjectKeyIdentifier,
        (struct casn *)&extp->extnValue.subjectKeyIdentifier) != 0)
        return ERR_SCM_INVALSKI;
      }
      // or if it's the IP addr extension
    else if (!memcmp(oidp, id_pe_ipAddrBlock, strlen(oidp)))
      {
      all_extns |= HAS_EXTN_IPADDR;
        // start at first family in cert. NOTE order must be v4 then v6, per 
        // RFC3779
      struct IPAddressFamilyA *rpAddrFamp = 
        &extp->extnValue.ipAddressBlock.iPAddressFamilyA;
      read_casn(&rpAddrFamp->addressFamily, cfam);
        // for ieach of the ROA's families
      struct ROAIPAddressFamily *ripAddrFamp;
      for (ripAddrFamp = &rp->content.signedData.encapContentInfo.eContent.
        roa.ipAddrBlocks.rOAIPAddressFamily;
        /* iRes == cTRUE && */ ripAddrFamp;
        ripAddrFamp = (struct ROAIPAddressFamily *)next_of(&ripAddrFamp->self))
        {  // find that family in cert
        read_casn(&ripAddrFamp->addressFamily, rfam);
        while (rpAddrFamp && memcmp(cfam, rfam, 2) != 0)
          {
          if (!(rpAddrFamp = (struct IPAddressFamilyA *)next_of(
            &rpAddrFamp->self)))
            iRes = ERR_SCM_INVALIPB;
          else  read_casn(&rpAddrFamp->addressFamily, cfam);
          }
            // OK, got the cert family, too f it's not inheriting
        if (iRes == 0 && 
          tag_casn(&rpAddrFamp->ipAddressChoice.self) == ASN_SEQUENCE) 
          {  // set up initial entry in cert
          struct IPAddressOrRangeA *rpAddrRangep = 
            &rpAddrFamp->ipAddressChoice.addressesOrRanges.iPAddressOrRangeA;
          if ((sta=setup_cert_minmax(rpAddrRangep, cmin, cmax, cfam[1])) < 0) 
            iRes = sta;
               // go through all ip addresses in that ROA family
          struct ROAIPAddress *roaAddrp;
          for (roaAddrp = &ripAddrFamp->addresses.rOAIPAddress; 
            roaAddrp && iRes == 0;
            roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
            {   // set up the limits
	    if ((sta = setup_roa_minmax(
                &roaAddrp->address, rmin, rmax, rfam[1])) < 0) iRes = sta;
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
                  // if roa min is below cert min OR roa max beyond cert max, 
                  // bail out
              if ((ii = memcmp(&rmin[2], &cmin[2], sizeof(cmin) - 2)) < 0 ||
                  (ij = memcmp(&rmax[2], &cmax[2], sizeof(cmin) - 2)) > 0) 
                  break;
              }
            }
          if (roaAddrp) iRes = ERR_SCM_INVALIPB;
          }
        }
      }
    free(oidp);
    }
  if (all_extns != (HAS_EXTN_IPADDR | HAS_EXTN_SKI)) iRes = ERR_SCM_INVALIPB;
  if (iRes == 0)  // check the signature
    {
    iRes = check_sig(rp, cert);
    }
  // delete_casn(&cert.self);
  return iRes;
  }
