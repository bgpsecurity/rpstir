#include "crlv2.h"

int CertificateRevocationListToBeSignedConstraint(
  struct CertificateRevocationListToBeSigned *ctbsp)
  {
  long version;
  int num = num_items(&ctbsp->extensions.self);
  read_casn_num(&ctbsp->version.self, &version);
  if (version <= 1 && num > 0) return 0;
  return 1;
 }
