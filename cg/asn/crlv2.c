#ifndef _crlv2_h
#include "crlv2.h"
#endif

void CertificateRevocationList(struct CertificateRevocationList *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CertificateRevocationListToBeSigned(&mine->toBeSigned, level);
    AlgorithmIdentifier(&mine->algorithm, level);
    simple_constructor(&mine->signature, level, ASN_BITSTRING);
    mine->signature.flags |= ASN_LAST_FLAG;
    }

void CertificateRevocationListToBeSigned(struct CertificateRevocationListToBeSigned *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CrlVersion(&mine->version, level);
    mine->version.self.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->version.v1.flags |= ASN_DEFAULT_FLAG;
    AlgorithmIdentifier(&mine->signature, level);
    Name(&mine->issuer, level);
    ChoiceOfTime(&mine->lastUpdate, level);
    ChoiceOfTime(&mine->nextUpdate, level);
    RevokedCertificatesInCertificateRevocationListToBeSigned(&mine->revokedCertificates, level);
    mine->revokedCertificates.self.flags |= ASN_OPTIONAL_FLAG;
    CrlExtensions(&mine->extensions, level);
    mine->extensions.self.tag = 0xA0;
    mine->extensions.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    mine->extensions.self.flags |= ASN_LAST_FLAG;
    }

void RevokedCertificatesInCertificateRevocationListToBeSigned(struct RevokedCertificatesInCertificateRevocationListToBeSigned *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    CRLEntry(&mine->cRLEntry, level);
    mine->cRLEntry.self.flags |= ASN_LAST_FLAG;
    }

void CrlVersion(struct CrlVersion *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_INTEGER);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->v1, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v1, (ulong)0);
    tagged_constructor(&mine->v2, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v2, (ulong)1);
    mine->v2.flags |= ASN_LAST_FLAG;
    }

int CrlVersionConstraint(struct CrlVersion *casnp)
    {
    long val;
    if (read_casn_num((struct casn *)casnp, &val) < 0) return 0;
    if (!diff_casn(&casnp->self, &casnp->v1) ||
        !diff_casn(&casnp->self, &casnp->v2)) return 1;
    return 0;
    }

void CRLEntry(struct CRLEntry *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->userCertificate, level, ASN_INTEGER);
    ChoiceOfTime(&mine->revocationDate, level);
    CrlEntryExtensions(&mine->extensions, level);
    mine->extensions.self.flags |= ASN_OPTIONAL_FLAG;
    mine->extensions.self.flags |= ASN_LAST_FLAG;
    }

void ChoiceOfTime(struct ChoiceOfTime *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->utcTime, level, ASN_UTCTIME);
    simple_constructor(&mine->generalTime, level, ASN_GENTIME);
    mine->generalTime.flags |= ASN_LAST_FLAG;
    }

