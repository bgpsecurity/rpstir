#ifndef _certificate_h
#include "certificate.h"
#endif

void CertificationPath(struct CertificationPath *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Certificate(&mine->userCertificate, level);
    TheCACertificatesInCertificationPath(&mine->theCACertificates, level);
    mine->theCACertificates.self.flags |= ASN_OPTIONAL_FLAG;
    mine->theCACertificates.self.flags |= ASN_LAST_FLAG;
    }

void TheCACertificatesInCertificationPath(struct TheCACertificatesInCertificationPath *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    CertificatePair(&mine->certificatePair, level);
    mine->certificatePair.self.flags |= ASN_LAST_FLAG;
    }

void CertificatePair(struct CertificatePair *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Certificate(&mine->forward, level);
    mine->forward.self.tag = 0xA0;
    mine->forward.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    Certificate(&mine->reverse, level);
    mine->reverse.self.tag = 0xA1;
    mine->reverse.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    mine->reverse.self.flags |= ASN_LAST_FLAG;
    }

void Certificate(struct Certificate *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CertificateToBeSigned(&mine->toBeSigned, level);
    AlgorithmIdentifier(&mine->algorithm, level);
    simple_constructor(&mine->signature, level, ASN_BITSTRING);
    mine->signature.flags |= ASN_LAST_FLAG;
    }

void CertificateToBeSigned(struct CertificateToBeSigned *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Version(&mine->version, level);
    mine->version.self.tag = 0xA0;
    mine->version.self.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG | ASN_EXPLICIT_FLAG;
    mine->version.v1.flags |= ASN_DEFAULT_FLAG;
    simple_constructor(&mine->serialNumber, level, ASN_INTEGER);
    AlgorithmIdentifier(&mine->signature, level);
    Name(&mine->issuer, level);
    Validity(&mine->validity, level);
    Name(&mine->subject, level);
    SubjectPublicKeyInfo(&mine->subjectPublicKeyInfo, level);
    tagged_constructor(&mine->issuerUniqueID, level, ASN_BITSTRING, 0x81);
    mine->issuerUniqueID.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->subjectUniqueID, level, ASN_BITSTRING, 0x82);
    mine->subjectUniqueID.flags |= ASN_OPTIONAL_FLAG;
    Extensions(&mine->extensions, level);
    mine->extensions.self.tag = 0xA3;
    mine->extensions.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    mine->extensions.self.flags |= ASN_LAST_FLAG;
    }

void Version(struct Version *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_INTEGER);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->v1, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v1, (ulong)0);
    tagged_constructor(&mine->v2, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v2, (ulong)1);
    tagged_constructor(&mine->v3, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v3, (ulong)2);
    mine->v3.flags |= ASN_LAST_FLAG;
    }

int VersionConstraint(struct Version *casnp)
    {
    long val;
    if (read_casn_num((struct casn *)casnp, &val) < 0) return 0;
    if (!diff_casn(&casnp->self, &casnp->v1) ||
        !diff_casn(&casnp->self, &casnp->v2) ||
        !diff_casn(&casnp->self, &casnp->v3)) return 1;
    return 0;
    }

void Validity(struct Validity *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CertificateValidityDate(&mine->notBefore, level);
    CertificateValidityDate(&mine->notAfter, level);
    mine->notAfter.self.flags |= ASN_LAST_FLAG;
    }

void CertificateValidityDate(struct CertificateValidityDate *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->utcTime, level, ASN_UTCTIME);
    simple_constructor(&mine->generalTime, level, ASN_GENTIME);
    mine->generalTime.flags |= ASN_LAST_FLAG;
    }

void SubjectPublicKeyInfo(struct SubjectPublicKeyInfo *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    AlgorithmIdentifier(&mine->algorithm, level);
    simple_constructor(&mine->subjectPublicKey, level, ASN_BITSTRING);
    mine->subjectPublicKey.flags |= ASN_LAST_FLAG;
    }

void Certificates(struct Certificates *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Certificate(&mine->certificate, level);
    ForwardCertificationPath(&mine->certificationPath, level);
    mine->certificationPath.self.flags |= ASN_OPTIONAL_FLAG;
    mine->certificationPath.self.flags |= ASN_LAST_FLAG;
    }

void ForwardCertificationPath(struct ForwardCertificationPath *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    CrossCertificates(&mine->crossCertificates, level);
    mine->crossCertificates.self.flags |= ASN_LAST_FLAG;
    }

void CrossCertificates(struct CrossCertificates *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    Certificate(&mine->certificate, level);
    mine->certificate.self.flags |= ASN_LAST_FLAG;
    }

