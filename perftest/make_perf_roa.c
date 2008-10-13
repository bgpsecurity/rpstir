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
  printf("%s -r roafile -c ee_certfile -k keyfile -a asnum [-R readable] [-b]\n", prog);
  printf("    [-4 [v4maxlen | cv4choicenum]] [-6 [v6maxlen | cv6choicenum]]\n");
  printf("  -r roafile: file to write roa to\n");
  printf("  -c ee_certfile: file holding EE cert for roa\n");
  printf("  -k keyfile: file holding p15-format public key for signing roa\n");
  printf("  -a asnum: autonomous system number\n");
  printf("  -R readable-version: where to write readable asn.1 for roa\n");
  printf("  -b: generate bad (invalid) signature\n");
  printf("  -4: specify maxLength for first IPv4 Address\n");
  printf("  -6: specify maxLength for first IPv6 Address\n");
  exit(1);
}

char *msgs[] =
  {
  "unused 1\n", 		// 0
  "IPAddress block has range\n",
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

// copy the ip addr blocks over into the roa
static void getIPAddresses(struct ROAIPAddrBlocks *roaipp,
   struct IpAddrBlock *ipap, int v4maxLen, int v6maxLen, int v4choice,
   int v6choice)
  {
  int numfams = 0;
  struct IPAddressFamilyA *ipFamp;
    // copy all families from the cert (ipap) to the ROA (roaipp)
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(&ipap->self, 0);
       ipFamp;
       ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {

    // insert a slot for the new family
    struct ROAIPAddressFamily *roafp = (struct ROAIPAddressFamily *)
      inject_casn(&roaipp->self, numfams++);

    // copy over the family ID (v4 or v6)
    copy_casn(&roafp->addressFamily, &ipFamp->addressFamily);
    uchar fam[2];
    read_casn(&ipFamp->addressFamily, fam);

    struct IPAddressOrRangeA *ipaorrp;
    int choice = (fam[1] == 1)? v4choice: v6choice; // specified choice?
    int numAddr = 0, numwritten = 0;
    for (ipaorrp = (struct IPAddressOrRangeA *) member_casn(
      &ipFamp->ipAddressChoice.addressesOrRanges.self, 0);
      ipaorrp; numAddr++,
      ipaorrp = (struct IPAddressOrRangeA *)next_of(&ipaorrp->self))
      {
      if (choice >= 0 && choice != numAddr) continue; // skip others
      // insert the casn for the ip addr
      struct ROAIPAddress *roaipa = (struct ROAIPAddress *) inject_casn(
        &roafp->addresses.self, numwritten++);
      // if cert has a range, give up
      if (size_casn(&ipaorrp->addressRange.self)) fatal(1, "");
      // otherwise copy the prefix
      copy_casn(&roaipa->address, &ipaorrp->addressPrefix);
      if (!numAddr) // only on first
        {
        if (fam[1] == 1 && v4maxLen > 0)
          write_casn_num(&roaipa->maxLength, (long)v4maxLen);
        if (fam[1] == 2 && v6maxLen > 0)
          write_casn_num(&roaipa->maxLength, (long)v6maxLen);
        }
      }
    }
  // all done
  return;
  }

int main (int argc, char **argv)
{
    long asnum = -1, bad = 0;
    char *ee_certfile = NULL, *roafile = NULL, *keyfile = NULL,
      *readablefile = NULL, *ca_certfile = NULL;
    struct ROA roa;
    struct Certificate cert, pcert;
    char *msg;
    int c;
    int v4maxLen = 0, v6maxLen = 0;
    int v4choice = -1, v6choice = -1;
    char *vx = (char *)0;

    int	roaVersion = 0;
    int	fValidate = 0;
    int	fDebug = 0;
    int	f = 0;

    while ((c = getopt(argc, argv, "dnbr:R:a:c:k:4:6:v:p:")) != -1) {
	switch (c) {
	case'R':
	  readablefile = strdup( optarg);
	  break;

	case 'r':
	  // roa file
	  roafile = strcpy( calloc( 1, strlen( optarg) + 5), optarg);
	  strcat( roafile, ".roa");
	  break;
                  
	case 'a':
	    asnum = atoi(optarg);
	    break;

	case 'b':
	    // mark sig as bad
	    bad = 1;
	    break;

	case 'v':
	    // Insert this (specified) eContent version
	    roaVersion = atoi(optarg);
	    break;

        case '4':
            // maxLength of first IPv4 address
	    vx = strdup(optarg);
            if (*vx <= '9') v4maxLen = atoi(vx);
            else v4choice = atoi(&vx[1]);
            free(vx);
            break;

        case '6':
            // maxLength of first IPv6 address
            vx = strdup(optarg);
            if (*vx <= '9') v6maxLen = atoi(vx);
            else v6choice = atoi(&vx[1]);
            free(vx);
            break;

	case 'c':
	  /*
	   * EE Certificate file
	   */
	  ee_certfile = strdup( optarg);
	  break;

	case 'p':
	  /*
	   * Parent (issuing) certificate
	   */
	  ca_certfile = strdup( optarg);
	  break;

	case 'k':
	  /*
	   * Signing key file
	   */
	  keyfile = strdup( optarg);
	  break;

	case 'n':
	  // We don't need to validate this because we're doing something purposely invalid
	  fValidate = 1;
	  break;

	case 'd':
	  fDebug = 1;
	  break;

	default:
	    printf("illegal option.\n");
	    usage(argv[0]);
	}
    }

    if ( roafile == (char* )NULL ) {
      usage(argv[0]);
      exit( 1);
    }

#if 0
    if ( readablefile == (char* )NULL ) {
      readablefile = strdup( roafile);
      strcpy( strrchr( readablefile, (int)'.'), ".raw");
    }
#endif

    if ( !strstr( roafile, ".roa") ) {
      fprintf( stderr, "Invalid ROA file name, must end with \".roa\": %s\n", roafile);
      exit( 1);
    }

    if ( ee_certfile == (char* )NULL ) {
      ee_certfile =
	(char* )strcpy( calloc( 1, strlen( roafile) + 5), roafile);

      
      *ee_certfile = 'C';

      strcpy( strstr( ee_certfile, ".roa"), "R.cer");
      if ( (f = open( ee_certfile, O_RDONLY)) < 0 ) {
	memmove( &ee_certfile[ 3 ], ee_certfile, strlen( ee_certfile) + 1);
	strncpy( ee_certfile, "../", 3);
	if ( (f = open( ee_certfile, O_RDONLY)) < 0 ) {
	  fprintf( stderr, "Cannot open EE-CERT file %s\n", ee_certfile);
	  exit( 1);
	}
      }
      close( f);
    }

    if ( (f = open( ee_certfile, O_RDONLY)) < 0 ) {
	fprintf( stderr, "Cannot open EE-CERT file %s\n", ee_certfile);
	exit( 1);
    }
    close( f);

    if ( ca_certfile == (char* )NULL ) {
      ca_certfile =
	(char* )strcpy( calloc( 1, strlen( roafile) + 4), roafile);


      *ca_certfile = 'C';

      *strstr( ca_certfile, ".roa") = '\0';
      strcpy( &ca_certfile[ strlen( ca_certfile) ], ".cer");

      if ( (f = open( ca_certfile, O_RDONLY)) < 0 ) {
	memmove( &ca_certfile[ 3 ], ca_certfile, strlen( ca_certfile) + 1);
	strncpy( ca_certfile, "../", 3);
	if ( (f = open( ca_certfile, O_RDONLY)) < 0 ) {
	  fprintf( stderr, "Cannot open CA-CERT file %s\n", ca_certfile);
	  exit( 1);
	}
      }
      close( f);
    }

    if ( (f = open( ca_certfile, O_RDONLY)) < 0 ) {
      fprintf( stderr, "Cannot open CA-CERT file %s\n", ca_certfile);
      exit( 1);
    }
    close( f);

    if ( keyfile == (char* )NULL ) {
      keyfile = strdup( ca_certfile);
      strcpy( strrchr( keyfile, (int)'.'), ".p15");
    }

    if ( (f = open( keyfile, O_RDONLY)) < 0 ) {
	fprintf( stderr, "Cannot open Signing KEY file %s\n", keyfile);
	exit( 1);
    }
    close( f);

    if ( (asnum == -1) && (ee_certfile != (char* )NULL) ) {
      char*	tmp_certfile =
	(char* )strcpy( (char *)calloc(1, strlen( ee_certfile)), &ee_certfile[ 1 ]);
      char*	tmpAsnum = (char *)calloc(1, strlen( ee_certfile));

      char*	tc = tmp_certfile;
      char*	ta = tmpAsnum;

      /*
       * Pick up the AS number from the file name
       *
       * Cxx.yyyy.zzz.cer
       * AS = xxyyyyzzz
       */
      tc = strtok( tmp_certfile, ".");
      while ( tc != (char* )NULL ) {
	strcpy( &tmpAsnum[ strlen( tmpAsnum) ], tc);
	tc = strtok( NULL, ".");
      }

      asnum = strtol( tmpAsnum, &ta, 10);
    }

    if ( fDebug ) {
      printf( "ASNUM:\t%d\n", (int )asnum);
      printf( "ROA:\t%s\n", roafile);
      printf( "CERT:\t%s\n", ee_certfile);
      printf( "PCERT:\t%s\n", ca_certfile);
      printf( "KEY:\t%s\n", keyfile);
    }

    // validate arguments
    if (roafile == NULL || ee_certfile == NULL || asnum < 0 || keyfile == NULL) {
	printf("%s -r %s -c %s -k %s ", argv[0], roafile, ee_certfile, keyfile);
	if (readablefile)
	    printf("-R %s ", readablefile);
	if (bad)
	    printf("-b ");
	if (asnum >= 0)
	    printf("-a %ld ", asnum);
	printf("\n");
	usage(argv[0]);
    }

    if (v4choice >= 0  || v6choice >= 0) {
      char midfix[8];
      *midfix = '.';
      midfix[1] = '4';
      midfix[2] = (v4choice < 0) ?'n': (char )(v4choice + '0');
      midfix[3] = '6';
      midfix[4] = (v6choice < 0) ?'n': (char )(v6choice + '0');
      midfix[5] = 0;
      char *fname = (char *)calloc(1, strlen(roafile) + 10);
      char *b = strrchr(roafile, (int)'.');
      strncpy(fname, roafile, (b - roafile));
      strcat(strcat(fname, midfix), b);
      free(roafile);
      roafile = fname;
      if ( readablefile != (char* )NULL ) {
	free( readablefile);
	fname = (char *)calloc(1, strlen(roafile) + 2);
	strcpy(fname, roafile);
	free(readablefile);
	readablefile = fname;
	for (b = readablefile; *b ; b++);
	strcpy(&b[-2], "aw");
      }
    }

    // init roa
    ROA(&roa, (ushort)0);
    write_objid(&roa.contentType, id_signedData);

    // init and read in the ee cert
    Certificate(&cert, (ushort)0);
    if (get_casn_file(&cert.self, ee_certfile, 0) < 0)
	fatal(2, ee_certfile);

    // init and read in the parent cert
    Certificate(&pcert, (ushort)0);
    if (get_casn_file(&pcert.self, ca_certfile, 0) < 0)
	fatal(2, ca_certfile);

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

    struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;

    // Insert the (optional) ROA version number
    write_casn_num( &(roap->version.self), roaVersion);

    // insert the AS number
    // note that as numbers are not supposed to be in ee certs
    write_casn_num(&roap->asID, asnum);

    // look up the ipAddrBlock extension and copy over
    struct Extension *extp;
    extp = (struct Extension *)member_casn(&pcert.toBeSigned.extensions.self, 0);
    while (extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock) != 0)
	extp = (struct Extension *)next_of(&extp->self);
    if (extp == NULL)
	fatal(3, "IP Address Block");
    getIPAddresses(&roap->ipAddrBlocks, &extp->extnValue.ipAddressBlock,
      v4maxLen, v6maxLen, v4choice, v6choice);

    // sign the message
    msg = signCMS(&roa, keyfile, bad);
    if (msg != NULL)
	fatal(7, msg);

    if ( fValidate ) 
      {
	int	ret = roaValidate( &roa);


	// validate: make sure we did it all right
	if ( ret < 0 ) {
	  fprintf( stderr, "Warning: %s failed roaValidate (-b option %s) \n", 
		   roafile, (bad == 0 ? "not set": "set"));
	}
      }

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

    if ( fDebug ) {
      fprintf(stderr, "Finished %s OK\n", roafile);
    }
    return 0;
}
