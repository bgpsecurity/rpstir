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
 * Copyright (C) Raytheon BBN Technologies Corp. 2010.  All Rights Reserved.
 *
 * Contributor(s): Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "casn.h"
#include "roa.h"
#include "crlv2.h"

static char *msgs[] =
    {
    "Usage: name of input file\n",
    "Suffix missing in %s\n",
    "Unknown type %s\n",
    "Error reading at %s\n",
    };

void fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(1);
  }

int main(int argc, char ** argv)
  {
  struct ROA roa;
  struct Certificate certificate;
  struct CertificateRevocationList crl;
  char *buf;
  int bsize;


  if (argc < 2) fatal (0, (char *)0);
  char *p = strrchr(argv[1], (int)'.');
  if (!p) fatal(1, (char *)0);
  if (!strcmp(p, ".cer"))
    {
    Certificate(&certificate, (ushort)0);
    if (get_casn_file(&certificate.self, argv[1], 0) < 0) 
        fatal(3, casn_err_struct.asn_map_string);
    bsize = dump_size(&certificate.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&certificate.self, buf);
    printf(buf);
    free(buf);
    delete_casn(&certificate.self);
    }
  else if (!strcmp(p, ".crl"))
    {
    CertificateRevocationList(&crl, (ushort)0);
    if (get_casn_file(&crl.self, argv[1], 0) < 0) 
        fatal(3, casn_err_struct.asn_map_string);
    bsize = dump_size(&crl.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&crl.self, buf);
    printf(buf);
    free(buf);
    delete_casn(&crl.self);
    }
  else if (!strcmp(p, ".man") || !strcmp(p, ".mft") || !strcmp(p, ".mnf") || 
    !strcmp(p, ".roa") || !strcmp(p, ".rta"))
    {
    ROA(&roa, (ushort)0);
    if (get_casn_file(&roa.self, argv[1], 0) < 0) 
        fatal(3, casn_err_struct.asn_map_string);
    bsize = dump_size(&roa.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&roa.self, buf);
    printf(buf);
    free(buf);
    delete_casn(&roa.self);
    }
  else fatal(2, p);   
  exit(1);
  }
   
