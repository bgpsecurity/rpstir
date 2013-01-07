
#include "certificate.h"

int CertificateToBeSignedConstraint(
    struct CertificateToBeSigned *ctbsp)
{
    long version;
    int num = num_items(&ctbsp->extensions.self);
    read_casn_num(&ctbsp->version.self, &version);
    if (version <= 1 && num > 0)
        return 0;
    if (version == 0 && (size_casn(&ctbsp->issuerUniqueID) > 0 ||
                         size_casn(&ctbsp->subjectUniqueID) > 0))
        return 0;
    return 1;
}
