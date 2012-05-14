/*
  $Id: roa_validate.c 506 2008-06-03 21:20:05Z csmall $
*/


#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "roa_utils.h"
#include "cryptlib.h"
#include "logutils.h"
#include "hashutils.h"

int strict_profile_checks_cms = 0;

/*
  This file contains the functions that semantically validate the ROA.
  Any and all syntactic validation against existing structures is assumed
  to have been performed at the translation step (see roa_serialize.c).
*/

#define MINMAXBUFSIZE 20

extern int CryptInitState;

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
    if (cryptInit() != CRYPT_OK)
      return ERR_SCM_CRYPTLIB;
    CryptInitState = 1;
    }
  if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2))
    return ERR_SCM_CRYPTLIB;
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
  if (cryptCreateContext(&pubkeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA))
    return ERR_SCM_CRYPTLIB;
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

static int getTime(struct CertificateValidityDate *cvdp, int64_t *datep)
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
  int64_t lo, hi;
  struct CertificateToBeSigned *certtbsp = &certp->toBeSigned;

  if (read_casn_num(&certp->toBeSigned.version.self, (long*)&tmp) < 0 ||
    tmp != 2) return ERR_SCM_BADCERTVERS;
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
  int ski_lth = 0;
  int tmp2 = 0;
  for (extp = (struct Extension *)member_casn(&certtbsp->extensions.self, 0);
    extp; extp = (struct Extension *)next_of(&extp->self))
    {
    if (isEE && !diff_objid(&extp->extnID, id_basicConstraints) &&
	size_casn(&extp->extnValue.basicConstraints.cA) > 0)
	return ERR_SCM_NOTEE;
    if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier))
      {
      uchar *ski;
      ski_lth = readvsize_casn(&extp->extnValue.subjectKeyIdentifier, &ski);
#ifndef ANYSKI
      if (ski_lth != tmp || memcmp(khash, ski, ski_lth)) err = ERR_SCM_INVALSKI
#endif
      tmp2 += ski_lth;	/* dummy statement to make compiler happy */
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
	  return(ERR_SCM_BADMKHASH);
	}
    }
  bit_lth = vsize_casn(&fahp->hash);
  uchar *hashp = (uchar *)calloc(1, bit_lth);
  read_casn(&fahp->hash, hashp);
  if ( hash_lth != (bit_lth - 1) ||
       memcmp(&hashp[1], contentsp, hash_lth) != 0 )
    err = ERR_SCM_BADMFTHASH;
  free(hashp);
  if ( inhash != NULL && inhashtotlen >= hash_lth && inhashlen == 0 && err == 0 )
    memcpy(inhash, contentsp, hash_lth);
  free(contentsp);
  return err == 0 ? hash_lth : err;
}

static struct Attribute *find_unique_attr(struct SignedAttributes *attrsp, 
  char *oidp, int *nump)
  {
  struct Attribute *attrp, *ch_attrp = NULL;
  int num = 0;
  *nump = 0;
  for (attrp = (struct Attribute *)member_casn(&attrsp->self, num);
    attrp; attrp = (struct Attribute *)next_of(&attrp->self), num++)
    {
    if (!diff_objid(&attrp->attrType, oidp))
      {
      (*nump)++;
      if (ch_attrp)           // attribute encountered already
        return NULL;
      ch_attrp = attrp;
      }
    }
  // make sure there is one and only one attrValue in the attribute
  if (ch_attrp && num_items(&ch_attrp->attrValues.self) != 1)
    return NULL;
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

static int test_maxLength(struct ROAIPAddress *roaAddrp, int familyMaxLength)
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
  if (maxLength > familyMaxLength) return ERR_SCM_INVALIPL;
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
  int family = 0;
  for (roaipfamp = (struct ROAIPAddressFamily *)member_casn(
    &ipAddrBlockp->self, 0); roaipfamp;
    roaipfamp = (struct ROAIPAddressFamily *)next_of(&roaipfamp->self),
    num++)
    {
    if ((i = read_casn(&roaipfamp->addressFamily, rfam)) < 0 || i > 2 ||
	rfam[0] != 0 || (rfam[1] != 1 && rfam[1] != 2)) return ERR_SCM_INVALFAM;
    family = rfam[1];
    if (num == 1 && family == 1) return ERR_SCM_INVALFAM; 
    for (roaAddrp = &roaipfamp->addresses.rOAIPAddress; roaAddrp;
      roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
      {
      int siz = vsize_casn(&roaAddrp->address);
      if ((family == 1 && siz > 5) || (family == 2 && siz > 17))
          return ERR_SCM_INVALIPL;        
      int familyMaxLength = 0;
      if (family == 1) familyMaxLength = 32;
      if (family == 2) familyMaxLength = 128;
      if ((err = test_maxLength(roaAddrp, familyMaxLength)) < 0 ||
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
	return ERR_SCM_BADCMSVER;

  // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (num_items(&rp->content.signedData.digestAlgorithms.self) != 1)
    return ERR_SCM_BADNUMDALG;
  if (diff_objid(&rp->content.signedData.digestAlgorithms.
      cMSAlgorithmIdentifier.algorithm, id_sha256))
	return ERR_SCM_BADDA;

  if ((num_certs = num_items(&rp->content.signedData.certificates.self)) > 1)
	return ERR_SCM_BADNUMCERTS;

  if (num_items(&rp->content.signedData.signerInfos.self) != 1)
	return ERR_SCM_NUMSIGINFO;

  sigInfop = (struct SignerInfo *)member_casn(&rp->content.signedData.
    signerInfos.self, 0);
  memset(digestbuf, 0, 40);

  if (diff_casn_num(&sigInfop->version.self, 3)) return ERR_SCM_SIGINFOVER; 
  if (!size_casn(&sigInfop->sid.subjectKeyIdentifier)) 
    return ERR_SCM_SIGINFOSID;
  if (diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256))
     return ERR_SCM_BADHASHALG;

  if (!num_items(&sigInfop->signedAttrs.self)) return ERR_SCM_BADSIGATTRS;
  struct Attribute *attrp;
  int num;
  // make sure there is one and only one content
  if (!(attrp = find_unique_attr(&sigInfop->signedAttrs, id_contentTypeAttr,
    &num)) ||
  // make sure it is the same as in EncapsulatedContentInfo
      diff_casn(&attrp->attrValues.array.contentType, 
      &rp->content.signedData.encapContentInfo.eContentType)) 
      return ERR_SCM_BADCONTTYPE;  
  // make sure there is one and only one message digest
  if (!(attrp = find_unique_attr(&sigInfop->signedAttrs, 
    id_messageDigestAttr, &num)) ||
  // make sure the message digest is 32 bytes long and we can get it
     vsize_casn(&attrp->attrValues.array.messageDigest) != 32 ||
     read_casn(&attrp->attrValues.array.messageDigest, digestbuf) != 32)
     return ERR_SCM_BADMSGDIGEST;

  // if there is a signing time, make sure it is the right format
  attrp = find_unique_attr(&sigInfop->signedAttrs, id_signingTimeAttr, &num);
  if (attrp)
    {
    uchar loctime[30];
    int usize, gsize;
    if ((usize = vsize_casn(&attrp->attrValues.array.signingTime.utcTime)) > 
       15 ||
       (gsize = vsize_casn(&attrp->attrValues.array.signingTime.
          generalizedTime)) > 17) return ERR_SCM_SIGINFOTIM;
    if (usize > 0) 
      {
      read_casn(&attrp->attrValues.array.signingTime.utcTime, loctime);
      if (loctime[0] <= '7' && loctime[0] >= '5') return ERR_SCM_SIGINFOTIM;
      }
    else
      {
      read_casn(&attrp->attrValues.array.signingTime.generalizedTime, 
        loctime);
      if (strncmp((char *)loctime, "2050", 4) < 0) return ERR_SCM_SIGINFOTIM;
      }
    }
  else if (num > 1) return ERR_SCM_SIGINFOTIM;
  // check that there is no more than one binSigning time attribute
  attrp = find_unique_attr(&sigInfop->signedAttrs, id_binSigningTimeAttr, &num);
  if (num > 1) return ERR_SCM_BINSIGTIME;
  // check the hash
  memset(hashbuf, 0, 40);
  // read the content
  tbs_lth = readvsize_casn(&rp->content.signedData.encapContentInfo.eContent.
    self, &tbsp);

  // hash it, make sure it's the right length and it matches the digest
  if (gen_hash(tbsp, tbs_lth, hashbuf, CRYPT_ALGO_SHA2) != 32 ||
	memcmp(digestbuf, hashbuf, 32) != 0) 
	ret =ERR_SCM_BADDIGEST; 
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
    if (!extp ||
        diff_casn(&extp->extnValue.subjectKeyIdentifier,
	&sigInfop->sid.subjectKeyIdentifier)) return ERR_SCM_SIGINFOSID;
    
  }

  // check that roa->content->crls == NULL
  if (size_casn(&rp->content.signedData.crls.self) > 0) return ERR_SCM_HASCRL; 

  // check that roa->content->signerInfo.digestAlgorithm == SHA-256
  //   (= OID 2.16.840.1.101.3.4.2.1)
  if (diff_objid(&rp->content.signedData.signerInfos.signerInfo.
    digestAlgorithm.algorithm, id_sha256))
	return ERR_SCM_BADDA;

  if (size_casn(&rp->content.signedData.signerInfos.signerInfo.unsignedAttrs.
    self) != 0)
	return ERR_SCM_UNSIGATTR;

  // check that roa->content->signerInfoStruct->signatureAlgorithm ==
  //    1.2.840.113549.1.1.11)
  struct casn *oidp = &rp->content.signedData.signerInfos.signerInfo.
                 signatureAlgorithm.algorithm;
  if (diff_objid(oidp, id_sha_256WithRSAEncryption))
      {
      if (strict_profile_checks_cms || diff_objid(oidp, id_rsadsi_rsaEncryption))
        {
        log_msg(LOG_ERR, "invalid signature algorithm in ROA");
        return ERR_SCM_BADSIGALG;
        }
      log_msg(LOG_WARNING, "deprecated signature algorithm in ROA");
      }

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

static int check_mft_version(struct casn *casnp)
  {
  long val = 0;
  int lth = read_casn_num(casnp, &val);

  if (lth < 0)
    return ERR_SCM_BADMANVER; // invalid read

  if (val != 0)
    return ERR_SCM_BADMANVER; // incorrect version number

  if (lth != 0)
    return ERR_SCM_BADMANVER; // explicit zero (should be implicit default)

  return 0;
  }

static int check_mft_number(struct casn *casnp)
  {
  int lth;
  long val;                                                      
  lth = read_casn_num(casnp, &val);
  if (lth <= 0 || val < 0) return ERR_SCM_BADMFTNUM;
  return 0;
  }

static int check_mft_dates(struct Manifest *manp, int * stalep)
  {
  time_t now;
  time(&now);
  int64_t thisUpdate, nextUpdate;
  if (read_casn_time(&manp->thisUpdate, &thisUpdate) < 0)
    {
    log_msg(LOG_ERR, "This update is invalid");
    return ERR_SCM_INVALDT;
    }
  if (thisUpdate > now)
    {
    log_msg(LOG_ERR, "This update in the future");
    return ERR_SCM_INVALDT;
    }
  if (read_casn_time(&manp->nextUpdate, &nextUpdate) < 0)
    {
    log_msg(LOG_ERR, "Next update is invalid");
    return ERR_SCM_INVALDT;
    }
  if (nextUpdate < thisUpdate)
    {
    log_msg(LOG_ERR, "Next update earlier than this update");
    return ERR_SCM_INVALDT;
    }
  if (now > nextUpdate)
    {
    *stalep = 1;
    }
  else
    {
    *stalep = 0;
    }
  return 0;
  }

static int check_mft_filenames(struct FileListInManifest *fileListp)
  {
  struct FileAndHash * fahp;
  char file[NAME_MAX];
  int file_length, i, filenum = 0;
  for (fahp = (struct FileAndHash *)member_casn(&fileListp->self, 0);
    fahp != NULL;
    fahp = (struct FileAndHash *)next_of(&fahp->self), filenum++)
    {
    if (vsize_casn(&fahp->file) > NAME_MAX)
      return ERR_SCM_BADMFTFILENAME;
    file_length = read_casn(&fahp->file, (unsigned char *)file);
    if (file_length <= 0)
      return ERR_SCM_BADMFTFILENAME;
    for (i = 0; i < file_length; ++i)
      {
      if (file[i] == '\0' || file[i] == '/')
        return ERR_SCM_BADMFTFILENAME;
      }
    if (file_length == 1 && file[0] == '.')
      return ERR_SCM_BADMFTFILENAME;
    if (file_length == 2 && file[0] == '.' && file[1] == '.')
      return ERR_SCM_BADMFTFILENAME;
    int hash_lth = vsize_casn(&fahp->hash);
    if (hash_lth != 33)
      return ERR_SCM_BADMFTHASH;
    }
  return 0;
  }

static int strcmp_ptr(const void *s1, const void *s2)
  {
  return strcmp(*(char const * const *)s1, *(char const * const *)s2);
  }

static int check_mft_duplicate_filenames(struct Manifest *manp)
  {
  struct FileAndHash * fahp;
  char ** filenames;
  int ret = 0;
  int file_length, total, i, j;
  total = num_items(&manp->fileList.self);
  filenames = malloc(total * sizeof(char *));
  if (filenames == NULL)
    {
    return ERR_SCM_NOMEM;
    }
  for (i = 0; i < total; ++i)
    {
    fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, i);
    file_length = vsize_casn(&fahp->file);
    filenames[i] = malloc(file_length + 1);
    if (filenames[i] == NULL)
      {
      for (j = 0; j < i; ++j)
        free(filenames[j]);
      free(filenames);
      return ERR_SCM_NOMEM;
      }
    read_casn(&fahp->file, (unsigned char *)filenames[i]);
    filenames[i][file_length] = '\0';
    }
  qsort(filenames, total, sizeof(char *), strcmp_ptr);
  for (i = 0; i < total; ++i)
    {
    if (ret == 0 && i + 1 < total)
      {
      if (strcmp(filenames[i], filenames[i+1]) == 0)
        {
        ret = ERR_SCM_MFTDUPFILE;
        }
      }
    free(filenames[i]);
    }
  free(filenames);
  return ret;
  }

/**=========================================================================
 * @brief Check conformance to manifest profile
 *
 * @param manp (struct ROA *)
 * @param stalep Return parameter to store whether or not the manifest is
 *               stale. It's value is only guaranteed to be initialized if
 *               this function returns 0.
 * @return 0 on success<br />a negative integer on failure
 *
 * Check manifest conformance with respect to the manifest profile
 *   (draft-ietf-sidr-rpki-manifests).
 *    
 * 4. Manifest definition 
 *
 * A manifest is an RPKI signed object, as specified in
 * [ID.sidr-signed-object].  The RPKI signed object template requires
 * specification of the following data elements in the context of the
 * manifest structure.
 *
 * 4.1 eContentType
 *
 * The eContentType for a Manifest is defined as id-ct-rpkiManifest, and
 * has the numerical value of 1.2.840.113549.1.9.16.1.26.
 *
 *   id-smime OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 *                                    rsadsi(113549) pkcs(1) pkcs9(9) 16 }
 *
 *   id-ct OBJECT IDENTIFIER ::= { id-smime 1 }
 *
 *   id-ct-rpkiManifest OBJECT IDENTIFIER ::= { id-ct 26 }
 *
 * 4.2 eContent
 *
 *   The content of a manifest is defined as follows:
 *
 * Manifest ::= SEQUENCE {
 *   version     [0] INTEGER DEFAULT 0,
 *   manifestNumber  INTEGER (0..MAX),
 *   thisUpdate      GeneralizedTime,
 *   nextUpdate      GeneralizedTime,
 *   fileHashAlg     OBJECT IDENTIFIER,
 *   fileList        SEQUENCE SIZE (0..MAX) OF FileAndHash
 *   }
 * 
 * FileAndHash ::=     SEQUENCE {
 *   file            IA5String,
 *   hash            BIT STRING
 *   }
 *   
 * 4.2.1 Manifest
 *
 *   The manifestNumber, thisUpdate, and nextUpdate fields are modeled
 *   after the corresponding fields in X.509 CRLs (see [RFC5280]).
 *   Analogous to CRLs, a manifest is nominally current until the time
 *   specified in nextUpdate or until a manifest is issued with a greater
 *   manifest number, whichever comes first.
 *
 *   If a "one-time-use" EE certificate is employed to verify a manifest,
 *   the EE certificate MUST have an validity period that coincides with
 *   the interval from thisUpdate to nextUpdate, to prevent needless
 *   growth of the CA's CRL.
 *
 *   If a "sequential-use" EE certificate is employed to verify a
 *   manifest, the EE certificate's validity period needs to be no shorter
 *   than the nextUpdate time of the current manifest.  The extended
 *   validity time raises the possibility of a substitution attack using a
 *   stale manifest, as described in Section 6.4.
 */
int manifestValidate(struct ROA *roap, int *stalep)
  {
/* Procedure:
   Step 1 Check that content type is id-ct-rpkiManifest
        2 Check version
        3 Check manifest number
        4 Check dates
        5 Check the hash algorithm
        6 Check the list of files and hashes
        7 Check general CMS structure
*/
  int iRes;
//                                                  step 1
  if (diff_objid(&roap->content.signedData.encapContentInfo.eContentType,
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
//                                                   step 2
  struct Manifest *manp = &roap->content.signedData.encapContentInfo.
    eContent.manifest;
  if (size_casn(&manp->self) <= 0) return ERR_SCM_BADCT;
  if ((iRes = check_mft_version(&manp->version.self)) < 0)
    return iRes;
//                                                    step 3
  if ((iRes = check_mft_number(&manp->manifestNumber)) < 0) 
    return iRes;
//                                                    step 4
  if ((iRes = check_mft_dates(manp, stalep)) < 0)
    return iRes;
//                                                   step 5
  if (diff_objid(&manp->fileHashAlg, id_sha256))
    {
    log_msg(LOG_ERR, "Incorrect hash algorithm");
    return ERR_SCM_BADHASHALG;
    }
                                                    // step 6
  if ((iRes = check_mft_filenames(&manp->fileList)) < 0)
    return iRes;
  iRes = check_mft_duplicate_filenames(manp);
  if (iRes < 0)
    return iRes;
                                                    // step 7
  iRes = cmsValidate(roap);
  if (iRes < 0) 
    return iRes;
  return 0;
  }

static int check_asnums(struct Certificate *certp, int iAS_ID)
  {
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&certp->toBeSigned.extensions.
    self, 0); 
    extp && diff_objid(&extp->extnID, id_pe_autonomousSysNum);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp) return 0;
  struct ASNumberOrRangeA *asNumOrRangeAp;
  if (size_casn(&extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.self))
    {
    int isWithin = 0;
    for (asNumOrRangeAp = (struct ASNumberOrRangeA *)member_casn(
      &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.self, 0);
      asNumOrRangeAp; asNumOrRangeAp = 
      (struct ASNumberOrRangeA *)next_of(&asNumOrRangeAp->self))
      {
      if (size_casn(&asNumOrRangeAp->num))
        {  
        if (!diff_casn_num(&asNumOrRangeAp->num, iAS_ID))
          {
          isWithin++;
          break;
          }
        }
      else // it's a range
        {
        if (diff_casn_num(&asNumOrRangeAp->range.min, iAS_ID) >= 0 &&
           diff_casn_num(&asNumOrRangeAp->range.max, iAS_ID) <= 0)
          {
          isWithin++;
          break;
          }
        }
      }
    if (!isWithin) return ERR_SCM_BADASNUM;  
    }
  return 1;
  }

struct certrange
  {
  uchar lo[18], hi[18];
  };

static int setuprange(struct certrange *certrangep, struct casn *lorangep, 
  struct casn *hirangep)
  { 
  uchar locbuf[18];
  memset(locbuf, 0, 18); 
  memset(certrangep->lo, 0, sizeof(certrangep->lo));
  memset(certrangep->hi, -1, sizeof(certrangep->hi));
  int lth = read_casn(lorangep, locbuf);   
  int unused = locbuf[0];
  memcpy(certrangep->lo, &locbuf[1], --lth);
  certrangep->lo[lth - 1] &= (0xFF << unused);
  lth = read_casn(hirangep, locbuf);
  unused = locbuf[0];
  memcpy(certrangep->hi, &locbuf[1], --lth);
  certrangep->hi[lth - 1] |= (0xFF >> (8 - unused));
  return 0;
  }

static int certrangecmp(const void * range1_voidp, const void * range2_voidp)
  {
  const struct certrange * range1 = (const struct certrange *)range1_voidp;
  const struct certrange * range2 = (const struct certrange *)range2_voidp;

  int ret = memcmp(range1->lo, range2->lo, sizeof(range1->lo));
  if (ret != 0)
    return ret;
  else
    return memcmp(range1->hi, range2->hi, sizeof(range1->hi));
  }

/** @return non-zero iff range1 fully contains range2 */
static int certrangeContains(
  const struct certrange * range1,
  const struct certrange * range2)
  {
    return memcmp(range2->lo, range1->lo, sizeof(range1->lo)) >= 0 &&
      memcmp(range2->hi, range1->hi, sizeof(range1->hi)) <= 0;
  }

/** @return non-zero iff range1 does not intersect range2
  and range1 is before range2 */
static int certrangeBefore(
  const struct certrange * range1,
  const struct certrange * range2)
  {
    return memcmp(range1->hi, range2->lo, sizeof(range1->hi)) < 0;
  }

static int checkIPAddrs(struct Certificate *certp, 
    struct ROAIPAddrBlocks *roaIPAddrBlocksp)
  {
// determine if all the address blocks in the ROA are within the EE cert
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&certp->toBeSigned.extensions.
    self, 0); 
    extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp) return 0;
  struct IpAddrBlock *certIpAddrBlockp = &extp->extnValue.ipAddressBlock;

  struct ROAIPAddressFamily *roaFamilyp;
  struct IPAddressFamilyA *certFamilyp;
  // for each ROA family, see if it is in cert
  for (roaFamilyp = (struct ROAIPAddressFamily *)member_casn(
    &roaIPAddrBlocksp->self, 0); roaFamilyp; 
    roaFamilyp = (struct ROAIPAddressFamily *)next_of(&roaFamilyp->self))
    {
    int matchedCertFamily = 0;
    for (certFamilyp = (struct IPAddressFamilyA *)member_casn(
      &certIpAddrBlockp->self, 0); certFamilyp; 
      certFamilyp = (struct IPAddressFamilyA *)next_of(&certFamilyp->self))
      {   
      if (diff_casn(&certFamilyp->addressFamily, &roaFamilyp->addressFamily))
        continue;
      matchedCertFamily = 1;
    // now at matching families. If inheriting, skip it
      if (size_casn(&certFamilyp->ipAddressChoice.inherit)) break;
      // for each ROA entry, see if it is in cert  
      const int roaNumPrefixes = num_items(&roaFamilyp->addresses.self);
      struct certrange * roaRanges =
        malloc(roaNumPrefixes * sizeof(struct certrange));
      if (!roaRanges) return ERR_SCM_NOMEM;
      struct ROAIPAddress *roaIPAddrp;
      int roaPrefixNum;
      for (roaIPAddrp = (struct ROAIPAddress *)member_casn(
        &roaFamilyp->addresses.self, 0), roaPrefixNum = 0;
        roaIPAddrp;
        roaIPAddrp = (struct ROAIPAddress *)next_of(&roaIPAddrp->self),
        ++roaPrefixNum)
        {
        // roaIPAddrp->address is a prefix (BIT string)
        setuprange(&roaRanges[roaPrefixNum], &roaIPAddrp->address, &roaIPAddrp->address);
        }
      qsort(roaRanges, roaNumPrefixes, sizeof(roaRanges[0]), certrangecmp);
      struct IPAddressOrRangeA *certIPAddressOrRangeAp =
        (struct IPAddressOrRangeA *)member_casn(
        &certFamilyp->ipAddressChoice.addressesOrRanges.self, 0);
      struct certrange certrange;
      roaPrefixNum = 0;
      while (roaPrefixNum < roaNumPrefixes)
        {
        do
          {
          if (certIPAddressOrRangeAp == NULL)
            {
            // reached end of certranges when there are still roaranges to match
            free(roaRanges);
            return ERR_SCM_ROAIPMISMATCH;
            }
          // certIPAddressOrRangep is either a prefix (BIT string) or a range
          if (size_casn(&certIPAddressOrRangeAp->addressRange.self))
            setuprange(&certrange, &certIPAddressOrRangeAp->addressRange.min,
              &certIPAddressOrRangeAp->addressRange.max);
          else setuprange(&certrange, &certIPAddressOrRangeAp->addressPrefix,
            &certIPAddressOrRangeAp->addressPrefix);
          certIPAddressOrRangeAp = (struct IPAddressOrRangeA*)
            next_of(&certIPAddressOrRangeAp->self);
          } while (!certrangeContains(&certrange, &roaRanges[roaPrefixNum]) &&
            !certrangeBefore(&roaRanges[roaPrefixNum], &certrange));
        if (!certrangeContains(&certrange, &roaRanges[roaPrefixNum]))
          {
          // roarange is unmatched and all remaining certrange are greater than roarange
          free(roaRanges);
          return ERR_SCM_ROAIPMISMATCH;
          }
        while (roaPrefixNum < roaNumPrefixes &&
          certrangeContains(&certrange, &roaRanges[roaPrefixNum]))
          {
          // skip all roaranges contained by this certrange
          ++roaPrefixNum;
          }
        }
      free(roaRanges);
      }
    if (!matchedCertFamily)
      return ERR_SCM_ROAIPMISMATCH;
    }
  return 1;
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

  struct RouteOriginAttestation *roap = &rp->content.signedData.
    encapContentInfo.eContent.roa;

  // check that the ROA version is right
  long val;
  if (read_casn_num(&roap->version.self, &val) != 0 || val != 0)
    return ERR_SCM_BADROAVER;
  // check that the asID is  a positive nonzero integer
  if (read_casn_num(&roap->asID, &iAS_ID) < 0 || iAS_ID <= 0) 
    return ERR_SCM_INVALASID;
  struct Certificate *certp = &rp->content.signedData.certificates.certificate;
  if (!certp) return ERR_SCM_BADNUMCERTS; // XXX: this never happens
  int rescount = 0;
  // check that the asID is within the EE cert's scope, if any
  if ((iRes = check_asnums(certp, iAS_ID)) < 0) return iRes;
  rescount += iRes; // count that we got an (optional) AS number extension
  iRes = 0;
  // check that the contents are valid
  struct ROAIPAddrBlocks *roaIPAddrBlocksp = &rp->content.signedData.
    encapContentInfo.eContent.roa.ipAddrBlocks;
  if ((iRes = validateIPContents(roaIPAddrBlocksp)) < 0) return iRes;
  // and that they are within the cert's resources
  if ((iRes = checkIPAddrs(certp, roaIPAddrBlocksp)) < 0)
    return iRes; 
  rescount += iRes;
  if (!rescount) return ERR_SCM_NOIPAS;
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
          {  // go through all ip addresses in that ROA family
          struct ROAIPAddress *roaAddrp;
          for (roaAddrp = &ripAddrFamp->addresses.rOAIPAddress; 
            roaAddrp && iRes == 0;
            roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
            {   // set up the limits
	    if ((sta = setup_roa_minmax(
                &roaAddrp->address, rmin, rmax, rfam[1])) < 0) iRes = sta;
              // first set up initial entry in cert
            struct IPAddressOrRangeA *rpAddrRangep = 
              &rpAddrFamp->ipAddressChoice.addressesOrRanges.iPAddressOrRangeA;
            if ((sta=setup_cert_minmax(rpAddrRangep, cmin, cmax, cfam[1])) < 0) 
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
