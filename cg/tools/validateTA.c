/*
  $Id validateTA.c 506 2008-06-03 21:20:05Z gardiner $
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
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <cryptlib.h>
#include <keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <certificate.h>
#include <roa.h>
#include <casn.h>
#include <err.h>

char *msgs[] = {
  "Finished OK\n",
  "Usage: names of CMS file, ETA certificate file, [RTA destination file]\n",
  "Invalid TA file %s\n",  // 2
  "Invalid %s\n",
  "CMS validation error %d\n",   // 4
  "Can't %s\n",
  }; 

static void fatal(int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  exit(0);
  }

static struct Attribute *find_attr(struct SignedAttributes *attrsp, char *oidp)
  {
  struct Attribute *attrp, *ch_attrp = NULL;
  int num = 0;
  for (attrp = (struct Attribute *)member_casn(&attrsp->self, 0);
    attrp; attrp = (struct Attribute *)next_of(&attrp->self))
    {
    if (!diff_objid(&attrp->attrType, oidp))
      {
      if (num++ ||
          num_items(&attrp->attrValues.self) != 1) return NULL;
      ch_attrp = attrp;
      }
    }
  return ch_attrp;
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

static int CryptInitState;

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
		    CRYPT_ALGO_TYPE alg)
  { // used for manifests      alg = 1 for SHA-1; alg = 2 for SHA2
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2)
      return ERR_SCM_BADALG;

  memset(hash, 0, 40);
  if (!CryptInitState)
    {
    cryptInit();
    CryptInitState = 1;
    }
  char *msg = NULL;
  if (cryptCreateContext(&hashContext, CRYPT_UNUSED, alg) < 0) msg = "create";
  else if (cryptEncrypt(hashContext, inbufp, bsize) < 0) msg = "encrypt 1";
  else if (cryptEncrypt(hashContext, inbufp,     0) < 0) msg = "encrypt 2";
  else if (cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, 
    &ansr) < 0) msg = "get attribute";
  else if (cryptDestroyContext(hashContext) < 0) msg = "destroy";
  else memcpy(outbufp, hash, ansr);
  if (msg) return -1;
  return ansr;
  }

static int check_cert_signature(struct Certificate *locertp, 
  struct Certificate *hicertp)
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
  bsize = size_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.self);
  if (bsize < 0) fatal(3, "lo cert size");
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.self, buf);
  sidsize = gen_hash(buf, bsize, sid, CRYPT_ALGO_SHA);
  free(buf);

  // generate the sha256 hash of the signed attributes. We don't call
  // gen_hash because we need the hashContext for later use (below).
  memset(hash, 0, 40);
  bsize = size_casn(&locertp->toBeSigned.self);
  if (bsize < 0) fatal(3, "sizing toBeSigned");
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&locertp->toBeSigned.self, buf);

  // (re)init the crypt library
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, buf, bsize);
  cryptEncrypt(hashContext, buf, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ret);
  free(buf);

  // get the public key from the certificate and decode it into an RSAPubKey
  readvsize_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey, &c);
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
  write_casn_num(&sigInfo.version.self, 3);
//  copy_casn(&sigInfo.version.self, &sigInfop->version.self); /* copy over */
//  copy_casn(&sigInfo.sid.self, &sigInfop->sid.self); /* copy over */
  write_casn(&sigInfo.sid.subjectKeyIdentifier, sid, sidsize); /* sid * hash */

  // copy over digest algorithm, signature algorithm, signature
  write_objid(&sigInfo.digestAlgorithm.algorithm, id_sha256);
  write_casn(&sigInfo.digestAlgorithm.parameters.sha256, (uchar *)"", 0);
  write_objid(&sigInfo.signatureAlgorithm.algorithm, id_rsadsi_rsaEncryption);
  write_casn(&sigInfo.signatureAlgorithm.parameters.rsadsi_rsaEncryption, 
    (uchar *)"", 0);
  uchar *sig;
  int siglth  = readvsize_casn(&locertp->signature, &sig);
  write_casn(&sigInfo.signature, &sig[1], siglth - 1);

  // now encode as asn1, and check the signature
  bsize = size_casn(&sigInfo.self);
  buf = (uchar *)calloc(1, bsize);
  encode_casn(&sigInfo.self, buf);
  ret = cryptCheckSignature(buf, bsize, pubkeyContext, hashContext);
  free(buf);

  // all done, clean up
  cryptDestroyContext(pubkeyContext);
  cryptDestroyContext(hashContext);
  delete_casn(&rsapubkey.self);
  delete_casn(&sigInfo.self);

  // if the value returned from crypt above != 0, it's invalid
  return ret;
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
    if (!diff_objid(&extp->extnID, id_basicConstraints) &&
	size_casn(&extp->extnValue.basicConstraints.cA) > 0)
	return ERR_SCM_NOTEE;
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

static int check_sig(struct ROA *rp, struct Certificate *certp)
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

    // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
    //   (= OID 2.16.840.1.101.3.4.2.1)
    if (num_items(&rp->content.signedData.digestAlgorithms.self) != 1 ||
	diff_objid(&rp->content.signedData.digestAlgorithms.
        cMSAlgorithmIdentifier.algorithm, id_sha256))
	return ERR_SCM_BADDA;

    if ((num_certs = num_items(&rp->content.signedData.certificates.self)) > 1)
	return ERR_SCM_BADNUMCERTS;
    struct Certificate *certp = (struct Certificate *)member_casn(
      &rp->content.signedData.certificates.self, 0); 
    if (num_items(&rp->content.signedData.crls.self)) return ERR_SCM_CRL;
    struct Extension *extp;
    for (extp = (struct Extension *)member_casn(
      &certp->toBeSigned.extensions.self, 0);
      extp && diff_objid(&extp->extnID, id_subjectKeyIdentifier);
      extp = (struct Extension *)next_of(&extp->self))
    if (!extp) return ERR_SCM_NOSKI;
    if (num_items(&rp->content.signedData.signerInfos.self) != 1)
	return ERR_SCM_BADSIGINFO;

    sigInfop = (struct SignerInfo *)member_casn(
      &rp->content.signedData.signerInfos.self, 0);
    memset(digestbuf, 0, 40);

    if (diff_casn_num(&sigInfop->version.self, 3) != 0 ||
        size_casn(&sigInfop->sid.subjectKeyIdentifier) <= 0 ||
        (diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256) &&
         diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha384) &&
         diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha512)) ||
        diff_casn(&extp->extnValue.subjectKeyIdentifier, 
          &sigInfop->sid.subjectKeyIdentifier) ||
        num_items(&sigInfop->unsignedAttrs.self))
        return ERR_SCM_BADSIGINFO;
   
    struct Attribute *attrp;
    // make sure there is content
    if (!(attrp = find_attr(&sigInfop->signedAttrs, id_contentTypeAttr)) ||
         diff_casn(&attrp->attrValues.array.contentType, 
            &rp->content.signedData.encapContentInfo.eContentType) ||
    // and messageDigest
        !(attrp = find_attr(&sigInfop->signedAttrs, id_messageDigestAttr)) ||
         vsize_casn(&attrp->attrValues.array.messageDigest) != 32 ||
         read_casn(&attrp->attrValues.array.messageDigest, digestbuf) != 32)
        return ERR_SCM_BADSIGINFO;
    /* skip signing time 
    if (!(attrp = find_attr(&sigInfop->signedAttrs, id_signingTimeAttr))) 
        return ERR_SCM_BADSIGINFO;
       // make sure it is the right format      
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
      read_casn(&attrp->attrValues.array.signingTime.generalizedTime, loctime);
      if (strncmp((char *)loctime, "2050", 4) < 0) return ERR_SCM_BADSIGINFO;
      }
   */
    // check the hash
    memset(hashbuf, 0, 40);
    // read the content
    tbs_lth = readvsize_casn(&rp->content.signedData.encapContentInfo.eContent.
      self, &tbsp);

    // hash it, make sure it's the right length and it matches the digest
    if (gen_hash(tbsp, tbs_lth, hashbuf, CRYPT_ALGO_SHA2) != 32 ||
	memcmp(digestbuf, hashbuf, 32) != 0) ret =  ERR_SCM_BADHASH;
    free(tbsp);			// done with the content now

    // if the hash didn't match, bail now
    if (ret != 0) return ret;

    // if there is a cert, check it
    if (num_certs > 0) 
      {
      struct Certificate *certp = (struct Certificate *)
	  member_casn(&rp->content.signedData.certificates.self, 0);
      if ((ret = check_cert(certp)) < 0) return ret;
      if ((ret = check_sig(rp, certp)) != 0) return ret;
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

int main(int argc, char **argv)
  {
  struct ROA roa;
  ROA(&roa, (ushort)0);
  struct Certificate etacert;
  Certificate(&etacert, (ushort)0);
  if (argc < 3) fatal(1, (char *)0);
  if (get_casn_file(&roa.self, argv[1], 0) < 0) fatal(2, argv[1]);
  if (get_casn_file(&etacert.self, argv[2], 0) < 0) fatal(2, argv[2]);
  int ansr = cmsValidate(&roa);
  if (ansr < 0) fatal(4, (char *)ansr);
  if (diff_objid(&roa.contentType, id_signedData)) 
    fatal(3, "content type" ); 
  if (diff_objid(&roa.content.signedData.encapContentInfo.eContentType, 
      id_ct_RPKITrustAnchor)) fatal(3, "eContentType");
  struct SignerInfos *signerInfosp = &roa.content.signedData.signerInfos;
  if (num_items(&signerInfosp->self) != 1) fatal(3, "number of SignerInfos");
  struct SignerInfo *signerInfop = (struct SignerInfo *)member_casn(
    &signerInfosp->self, 0);
  if (size_casn(&signerInfop->sid.subjectKeyIdentifier) <= 0) 
    fatal(3, "Signer identifier");
  struct Attribute *attrp;
  struct SignedAttributes *sigAttrsp = &signerInfop->signedAttrs;
  int num = num_items(&sigAttrsp->self);
  int j;
  for (j = 0; j < num; j++)
    {
    attrp = (struct Attribute *)member_casn(&sigAttrsp->self, j);
    if (!diff_objid(&attrp->attrType, id_contentTypeAttr)) break;
    }  
  if (j >= num) fatal(3, "content type attribute");
  for (j = 0; j < num; j++)
    {
    attrp = (struct Attribute *)member_casn(&sigAttrsp->self, j);
    if (!diff_objid(&attrp->attrType, id_messageDigestAttr)) break;
    }  
  if (j >= num) fatal(3, "message digest attribute");
  struct Certificate *rtacertp = &roa.content.signedData.encapContentInfo.  
    eContent.trustAnchor;
    
  if (check_cert_signature(rtacertp, rtacertp) < 0) fatal(2, "signature");
  if (num_items(&roa.content.signedData.certificates.self) != 1) 
    fatal(3, "number of certificates");
  struct Certificate *eecertp = (struct Certificate *)member_casn(&roa.content.
    signedData.certificates.self, 0);  
  if (check_cert_signature(eecertp, &etacert) < 0) 
    fatal(3, "EE certificate signature");
  if (argc > 2 && put_casn_file(&rtacertp->self, argv[3], 0) < 0) 
    fatal(5, "write RTA certificate");
  return 0;
  } 
