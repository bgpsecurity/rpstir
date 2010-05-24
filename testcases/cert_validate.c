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

char *msgs[] =
    {
    "Signature %s\n",
    "Args are locertfile hicertfile\n",
    "Can't get %s\n",
    "Signing error in %s\n", 
    };

static void fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(err);
  }

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
		    CRYPT_ALGO_TYPE alg)
  { // used for manifests      alg = 1 for SHA-1; alg = 2 for SHA2
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2) fatal(3, "algorithm");
      

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, alg);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static int check_signature(struct Certificate *locertp, 
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
  assert(ret == 32);		/* size of hash; should never fail */
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
  cryptEnd();
  delete_casn(&rsapubkey.self);
  delete_casn(&sigInfo.self);

  // if the value returned from crypt above != 0, it's invalid
  return ret;
  }

int main(int argc, char **argv)
  {
  if (argc != 3) fatal(1, (char *)0);
  struct Certificate locert, hicert;
  Certificate(&locert, (ushort)0);
  Certificate(&hicert, (ushort)0);
  if (get_casn_file(&locert.self, argv[1], 0) < 0) fatal(2, argv[1]);
  if (get_casn_file(&hicert.self, argv[2], 0) < 0) fatal(2, argv[2]);
  if (check_signature(&locert, &hicert) < 0) fatal(0, "Failed");
  fatal(0, "succeeded");
  return 0;
  }
