/* $Id: make_roa.c 453 2008-07-25 15:30:40Z cgardiner $ */

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
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles iW. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <certificate.h>
#include <extensions.h>
#include <roa.h>
#include <roa_utils.h>
#include <assert.h>

// in signCMS.c in this directory
extern char *signCMS(struct ROA *, char *, int);

void usage(char *prog) 
{
  printf("usage:\n");
  printf("%s -r roafile -c certfile -k keyfile -i index [-R readable] [-b]\n", prog);
  printf("  -r roafile: file to write roa to\n");
  printf("  -c certfile: file holding EE cert for roa\n");
  printf("  -k keyfile: file holding p15-format public key for signing roa\n");
  printf("  -i index: which child is this (of that cert) (one-based)\n");
  printf("  -R readable: file to write readable asn.1 for roa to\n");
  printf("  -b: generate bad (invalid) signature\n");
  exit(1);
}  

char *msgs[] =
  {
  "unused 1\n", 		// 0
  "unused 2\n",
  "Can't read %s\n",		// 2
  "Can't find %s extension in certificate\n",
  "Error writing %s\n",		// 4
  "Can't find extension %s\n",
  "Can't find ASNum[%d]\n",	// 6
  "Signature failed in %s\n",
  };

void fatal(int err, ...)
{
    va_list ap;
    va_start(ap, err);
    assert(err < (sizeof(msgs) / sizeof(msgs[0])));
    vfprintf(stderr, msgs[err], ap);
    va_end(ap);
    exit(err);
}

// look through the certificate's extensions for the idx'th asn 
static long getASNum(struct Certificate *certp, long idx)
{
  struct Extensions *extsp = &certp->toBeSigned.extensions;
  struct Extension *extp;
  struct ASNumberOrRangeA *asnump;
  long orig = idx;
  long min, max, range, ansr;

  // idx counts down, decrementing each time we see a single addr
  // or decrementing by the size of a range if we see a range

  // look for the ASN extension
  extp = (struct Extension *)member_casn(&extsp->self, 0); 
  while (extsp && diff_objid(&extp->extnID, id_pe_autonomousSysNum) != 0)
    extp = (struct Extension *) next_of(&extp->self);

  // did we find it?
  if (extp == NULL) 
    fatal(5, id_pe_autonomousSysNum);

  // now iterate through each AS number (or AS range) to find the idx'th one

  // XXX asnum is marked as optional in the spec
  // added this assert to make sure it's bound. is it right?
  struct ASIdentifierChoiceA *asnum = &extp->extnValue.autonomousSysNum.asnum;
  // N.b. if the length > 0, means that the field has a value
  assert(vsize_casn(&asnum->self) > 0);

  // run through the sequence, decrementing idx as we go past
  // when idx goes to 0, we've found our goal
  for (asnump = (struct ASNumberOrRangeA *) 
	 member_casn(&asnum->asNumbersOrRanges.self, 0);
       asnump != NULL;
       asnump = (struct ASNumberOrRangeA *)next_of(&asnump->self)) {

    // is this a singleton or a range?
    if (vsize_casn(&asnump->num) != 0) {
      // singleton
      if (--idx < 1) {
	// this is it, return it
        read_casn_num(&asnump->num, &ansr);
	return ansr;
      }
    } else {
      // it's a range, decrement idx by the size of the range
      read_casn_num(&asnump->range.min, &min);
      read_casn_num(&asnump->range.max, &max);
      range = max + 1 - min;

      // if idx > size, decrement by the entire size and
      // keep looking
      if (idx > range) {
	idx -= range;
      } else {
	// it's in this range, the answer is min + idx
        return (min + idx - 1);
      }
    }
  }

  // didn't find it, fail
  fatal(6, orig);
  return 0;
}

// copy the ip addr blocks over into the roa
static void getIPAddresses(struct ROAIPAddrBlocks *roaipp, 
			   struct IpAddrBlock *ipap)
  {
  int numfams = 0;
  struct IPAddressFamilyA *ipFamp;
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(&ipap->self, 0); 
       ipFamp;
       ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {

    // insert a slot for the new family
    struct ROAIPAddressFamily *roafp = (struct ROAIPAddressFamily *)
      inject_casn(&roaipp->self, numfams++);

    // copy over the family ID (v4 or v6)
    copy_casn(&roafp->addressFamily, &ipFamp->addressFamily);

      // XXX assume only 1 IPAddressOrRange in cert
    struct IPAddressOrRangeA *ipaorrp = (struct IPAddressOrRangeA *)
      member_casn(&ipFamp->ipAddressChoice.addressesOrRanges.self, 0);

    // insert the casn for the ip addr
    struct ROAIPAddress *roaipa = (struct ROAIPAddress *)
      inject_casn(&roafp->addresses.self, 0); 

    // XXX what is this? why are we changing the length of the prefix?
    uchar *addrp;
    int lth = readvsize_casn(&ipaorrp->addressPrefix, &addrp);
#if 0				
    /* I have no clue why this was here. */
    /* It munges prefix lengths for no clear reason. */
    if (addrp[0] > 1) 
      addrp[0] -= 2;
    else
      {
      addrp = (uchar *)realloc(addrp, ++lth);
      addrp[0] += 6;
      addrp[lth - 1] = 0;
      }
#endif
    // write the addr to the roa's field
    write_casn(&roaipa->address, addrp, lth);
    }

  // all done
  return;
  }

int main (int argc, char **argv)
{
    long asnum = -1, bad = 0;
    char *certfile = NULL, *roafile = NULL, *keyfile = NULL, *readablefile = NULL;
    struct ROA roa;
    struct Certificate cert;
    char *msg;
    int idx;
    int c;

    while ((c = getopt(argc, argv, "br:R:i:c:k:")) != -1) {
	switch (c) {
	case 'c':
	    // cert file
	    certfile = strdup(optarg);
	    break;

	case 'r':
	    // roa file
	    roafile = strdup(optarg);
	    break;

	case 'R':
	    // readable output file
	    readablefile = strdup(optarg);
	    break;

	case 'k':
	    // key file
	    keyfile = strdup(optarg);
	    break;

	case 'i':
	    // index (which child -- 1, 2, 3
	    idx = atoi(optarg);
	    break;

	case 'b':
	    // mark sig as bad
	    bad = 1;
	    break;

	default:
	    printf("illegal option.\n");
	    usage(argv[0]);
	}
    }

    // validate arguments
    if (roafile == NULL || certfile == NULL || idx < 1 || keyfile == NULL) {
	printf("%s -r %s -c %s -i %d -k %s ", argv[0], roafile, certfile, idx, keyfile);
	if (readablefile) 
	    printf("-R %s ", readablefile);
	if (bad) 
	    printf("-b ");
	printf("\n");
	usage(argv[0]);
    }

    // init roa
    ROA(&roa, (ushort)0);
    write_objid(&roa.contentType, id_signedData);

    // init and read in the ee cert
    Certificate(&cert, (ushort)0);
    if (get_casn_file(&cert.self, certfile, 0) < 0) 
	fatal(2, certfile);

    // mark the roa: the signed data is hashed with sha256
    struct SignedData *sgdp = &roa.content.signedData;
    write_casn_num(&sgdp->version.self, 3);
    struct AlgorithmIdentifier *algidp = (struct AlgorithmIdentifier *)
	inject_casn(&sgdp->digestAlgorithms.self, 0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *)"", 0);

    // insert the EE's cert
    struct Certificate *sigcertp = (struct Certificate *)
	inject_casn(&sgdp->certificates.self, 0);
    copy_casn(&sigcertp->self, &cert.self);

    // mark the encapsulated content as a ROA
    write_objid(&sgdp->encapContentInfo.eContentType, id_routeOriginAttestation);

    // look up and insert the AS number
    struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;
    asnum = getASNum(sigcertp, idx);
    write_casn_num(&roap->asID, asnum);

    // look up the ipAddrBlock extension and copy over
    struct Extension *extp;
    extp = (struct Extension *)member_casn(&cert.toBeSigned.extensions.self, 0);
    while (extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock) != 0)
	extp = (struct Extension *)next_of(&extp->self);
    if (extp == NULL) 
	fatal(3, "IP Address Block");
    getIPAddresses(&roap->ipAddrBlocks, &extp->extnValue.ipAddressBlock);

    // sign the message
    msg = signCMS(&roa, keyfile, bad);
    if (msg != NULL) 
	fatal(7, msg);

    // validate: make sure we did it all right
    if (roaValidate(&roa) != 0) 
	fprintf(stderr, "Warning: %s failed roaValidate (-b option %s) \n",
		roafile, (bad == 0 ? "not set":"set"));

    // write out the roa
    if (put_casn_file(&roa.self, roafile, 0) < 0) 
	fatal(4, roafile);

    // do they want readable output saved?
    if (readablefile != NULL) {
	int fd = open(readablefile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
	if (fd < 0) 
	    fatal(4, readablefile);
	int siz = dump_size(&roa.self);
	char *rawp = (char *)calloc(1, siz + 4);
	siz = dump_casn(&roa.self, rawp);
	if (write(fd, rawp, siz) < 0) 
	    perror(readablefile);
	close(fd);
	free(rawp);
    }

    fprintf(stderr, "Finished %s OK\n", roafile);
    return 0;
}  
