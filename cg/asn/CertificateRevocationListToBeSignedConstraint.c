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

#include "crlv2.h"

int CertificateRevocationListToBeSignedConstraint(
  struct CertificateRevocationListToBeSigned *ctbsp)
  {
  long version = 0;
  int num = num_items(&ctbsp->extensions.self);
  struct CRLEntry *crlentryp;
  for (crlentryp = (struct CRLEntry *)member_casn(
    &ctbsp->revokedCertificates.self, 0); crlentryp;
    crlentryp = (struct CRLEntry *)next_of(&crlentryp->self))  
    {
    if (vsize_casn(&crlentryp->extensions.self) > 0) num++;
    } 
  read_casn_num(&ctbsp->version.self, &version);
  if (version > 1 || (!version && num > 0)) return 0;
  return 1;
 }
