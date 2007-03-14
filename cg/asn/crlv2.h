#ifndef _crlv2_h
#define _crlv2_h

#ifndef _casn_h
#include "casn.h"
#endif
#ifndef _Algorithms_h
#include "Algorithms.h"
#endif
#ifndef _extensions_h
#include "extensions.h"
#endif
#ifndef _serial_number_h
#include "serial_number.h"
#endif
#ifndef _name_h
#include "name.h"
#endif

struct ChoiceOfTime
    {
    struct casn self;
    struct casn utcTime;
    struct casn generalTime;
    };

void ChoiceOfTime(struct ChoiceOfTime *mine, ushort level);

struct CRLEntry
    {
    struct casn self;
    struct casn userCertificate;
    struct ChoiceOfTime revocationDate;
    struct CrlEntryExtensions extensions;
    };

void CRLEntry(struct CRLEntry *mine, ushort level);

struct CrlVersion
    {
    struct casn self;
    struct casn v1;
    struct casn v2;
    };

void CrlVersion(struct CrlVersion *mine, ushort level);

int CrlVersionConstraint(struct CrlVersion *);

struct RevokedCertificatesInCertificateRevocationListToBeSigned
    {
    struct casn self;
    struct CRLEntry cRLEntry;
    };

void RevokedCertificatesInCertificateRevocationListToBeSigned(struct RevokedCertificatesInCertificateRevocationListToBeSigned *mine, ushort level);

struct CertificateRevocationListToBeSigned
    {
    struct casn self;
    struct CrlVersion version;
    struct AlgorithmIdentifier signature;
    struct Name issuer;
    struct ChoiceOfTime lastUpdate;
    struct ChoiceOfTime nextUpdate;
    struct RevokedCertificatesInCertificateRevocationListToBeSigned revokedCertificates;
    struct CrlExtensions extensions;
    };

void CertificateRevocationListToBeSigned(struct CertificateRevocationListToBeSigned *mine, ushort level);

int CertificateRevocationListToBeSignedConstraint(struct CertificateRevocationListToBeSigned *);

struct CertificateRevocationList
    {
    struct casn self;
    struct CertificateRevocationListToBeSigned toBeSigned;
    struct AlgorithmIdentifier algorithm;
    struct casn signature;
    };

void CertificateRevocationList(struct CertificateRevocationList *mine, ushort level);

#endif /* crlv2_h */
