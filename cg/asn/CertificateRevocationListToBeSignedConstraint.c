
#include "crlv2.h"

int CertificateRevocationListToBeSignedConstraint(
    struct CertificateRevocationListToBeSigned *ctbsp)
{
    long version = 0;
    int num = num_items(&ctbsp->extensions.self);
    struct CRLEntry *crlentryp;
    for (crlentryp =
         (struct CRLEntry *)member_casn(&ctbsp->revokedCertificates.self, 0);
         crlentryp; crlentryp = (struct CRLEntry *)next_of(&crlentryp->self))
    {
        if (vsize_casn(&crlentryp->extensions.self) > 0)
            num++;
    }
    read_casn_num(&ctbsp->version.self, &version);
    if (version > 1 || (!version && num > 0))
        return 0;
    return 1;
}
