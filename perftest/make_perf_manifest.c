/*
  $Id: make_manifest.c 453 2007-07-25 15:30:40Z gardiner $
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
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include "manifest.h"
#include "roa.h"
#include "certificate.h"
#include "cryptlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <asn.h>
#include <casn.h>

extern char *signCMS(struct ROA *roap, char *keyfile, int bad); 
/*
  This file has a program to make manifests.
*/

char *msgs [] = 
    {
    "Finished %s OK\n",
    "Couldn't open %s\n",      //1
    "Error reading %s\n",
    "Error adding %s\n",      // 3
    "Error inserting %s\n",   
    "Error creating signature\n",    // 5
    "Error writing %s\n",
    "Signature failed in %s\n",   // 7
    };
    
static int fatal(int msg, char *paramp);
static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp);

static int add_name(char *curr_file, struct Manifest *manp, int num, int bad)
  {
  int fd, siz, hsiz;
  uchar *b, hash[40];
  if ((fd = open(curr_file, O_RDONLY)) < 0) {
    perror( "open");
    fatal(1, curr_file);
  }
  siz = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, 0);
  b = (uchar *)calloc(1, siz);
  if (read(fd, b, siz + 2) != siz) fatal(2, curr_file);
  hsiz = gen_hash(b, siz, hash);
  if (bad) hash[1]++;
  struct FileAndHash *fahp;
  if (!(fahp = (struct FileAndHash *)inject_casn(&manp->fileList.self, num))) 
    fatal(3, "fileList");
  write_casn(&fahp->file, (uchar *)curr_file, strlen(curr_file));
  write_casn_bits(&fahp->hash, hash, hsiz, 0);
  return  1;
  }

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static int fatal(int msg, char *paramp)
  {
  fprintf(stderr, msgs[msg], paramp);
  exit(msg);
  }

int main(int argc, char **argv)
  {
  struct ROA roa;
  struct AlgorithmIdentifier *algidp;
  ulong now = time((time_t *)0);

  int	version = 0;
  int	fDebug = 0;
  int	f = 0;
  
  char	a;

  char* c = (char* )NULL;

  char*	manifestfile = (char* )NULL;
  char*	ee_certfile = (char* )NULL;
  char*	ca_certfile = (char* )NULL;
  char* keyfile = (char* )NULL;
  char*	timeDiffSpec = (char* )NULL;


  while ((a = getopt( argc, argv, "dm:R:c:k:p:v:t:")) != -1) {
    switch (a) {
    case 'm':
      /*
       * Manifest name
       */
      manifestfile = strdup( optarg);
      break;

    case 'c':
      /*
       * EE-Cert name
       */
      ee_certfile = strdup( optarg);
      break;

    case 'k':
      /*
       * Signing KEY name
       */
      keyfile = strdup( optarg);
      break;

    case 'p':
      /*
       * CA-Cert name
       */
      ca_certfile = strdup( optarg);
      break;

    case 't':
      timeDiffSpec = strdup( optarg);
      break;

    case 'v':
      /*
       * Manifest version
       */
      version = strtol( optarg, NULL, 0);
      break;

    case 'd':
      fDebug = 1;
      break;
    }
  }

  if ( manifestfile == (char* )NULL ) {
    exit( 1);
  }

  if ( ee_certfile == (char* )NULL ) {
    ee_certfile = strdup( manifestfile);
    *ee_certfile = 'C';
    strcpy( strrchr( ee_certfile, (int)'.'), "M.cer");

  }	    

  if ( (f = open( ee_certfile, O_RDONLY)) < 0 ) {
    fprintf( stderr, "Cannot open CA-CERT file %s\n", ee_certfile);
    exit( 1);
  }
  close( f);

  if ( ca_certfile == (char* )NULL ) {
    ca_certfile = (char* )calloc( 1, strlen( ee_certfile) + 3);

    sprintf( ca_certfile, "../%s", ee_certfile);
    if ( strstr( ca_certfile, "M.cer") ) {
      *(strstr( ca_certfile, "M.cer")) = '\0';
    }
    /*
    if ( strrchr( ca_certfile, '.') )
      *(strrchr( ca_certfile, '.')) = '\0';
      */
    strcpy( &ca_certfile[ strlen( ca_certfile) ], ".cer");
  }

  if ( (f = open( ca_certfile, O_RDONLY)) < 0 ) {
    fprintf( stderr, "Cannot open Parent-CERT file %s\n", ca_certfile);
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

  if ( fDebug ) {
    printf( "VERSION:\t%d\n", (int )version);
    printf( "ROA:\t%s\n", manifestfile);
    printf( "CERT:\t%s\n", ee_certfile);
    printf( "PCERT:\t%s\n", ca_certfile);
    printf( "KEY:\t%s\n", keyfile);
  }

  ROA(&roa, 0);
  write_objid(&roa.contentType, id_signedData);
  write_casn_num(&roa.content.signedData.version.self, (long)3);
  inject_casn(&roa.content.signedData.digestAlgorithms.self, 0);
  algidp = (struct AlgorithmIdentifier *)member_casn(&roa.content.signedData.
    digestAlgorithms.self, 0);
  write_objid(&algidp->algorithm, id_sha256);
  write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
  write_objid(&roa.content.signedData.encapContentInfo.eContentType, id_roa_pki_manifest);
  struct Manifest *manp = &roa.content.signedData.encapContentInfo.eContent.manifest;
  // Insert the (optional) ROA version number
  write_casn_num( &(manp->version.self), version);
  write_casn_num(&manp->manifestNumber, (long)index);
  int timediff = 0;

  if ( timeDiffSpec != (char* )NULL )
    {
    sscanf( timeDiffSpec, "%d", &timediff);
    char u = timeDiffSpec[strlen(timeDiffSpec) - 1];
    if (u == 'h') timediff *= 60;
    else if (u == 'D') timediff *= (3600 * 24);
    else if (u == 'W') timediff *= (3600 * 24 * 7);
    else if (u == 'M') timediff *= (3600 * 24 * 30);
    else if (u == 'M') timediff *= (3600 * 24 * 365);
    else fatal(2, timeDiffSpec);
    now += timediff;
    } 
  write_casn_time(&manp->thisUpdate, now);
  now += (30*24*3600);
  write_casn_time(&manp->nextUpdate, now);
  write_objid(&manp->fileHashAlg, id_sha256);
  
    // now get the files 
  char curr_file[128];
  memset(curr_file, 0, 128);

  int num = 0;

  while ( fgets( curr_file, sizeof( curr_file), stdin) ) {
    if ( strchr( curr_file, '\n') )
      *strchr( curr_file, '\n') = '\0';

    add_name( curr_file, manp, num, 0);

    num += 1;
  }

  if (!inject_casn(&roa.content.signedData.certificates.self, 0)) 
    fatal(4, "signedData");
  struct Certificate *certp = (struct Certificate *)member_casn(
    &roa.content.signedData.  certificates.self, 0);
  if (get_casn_file(&certp->self, ee_certfile, 0) < 0) fatal(2, ee_certfile);
  if ((c = signCMS(&roa, keyfile, 0))) fatal(7, c);
  if (put_casn_file(&roa.self, manifestfile, 0) < 0) fatal(6, manifestfile);
  for (c = manifestfile; *c && *c != '.'; c++);
  strcpy(c, ".raw");
  char *rawp;
  int lth = dump_size(&roa.self);
  rawp = (char *)calloc(1, lth + 4);
  dump_casn(&roa.self, rawp);
  int fd = open(manifestfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  write(fd, rawp, lth);
  close(fd);
  free(rawp);
  fatal(0, manifestfile);  
  return 0;
  } 
