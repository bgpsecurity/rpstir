#ifndef _certificate_h
#define _certificate_h

#ifndef _casn_h
#include "casn.h"
#endif
#ifndef _orname_h
#include "orname.h"
#endif
#ifndef _name_h
#include "name.h"
#endif
#ifndef _Algorithms_h
#include "Algorithms.h"
#endif
#ifndef _serial_number_h
#include "serial_number.h"
#endif
#ifndef _extensions_h
#include "extensions.h"
#endif
#define PKIX_EE 1
#define PKIX_PCA 2
#define PKIX_CA 3
#define MISSI_CROSSCERT 4
#define MISSI_EE 5
#define MISSI_SUB_CA 6
#define MISSI_CA 7
#define MISSI_PCA 8
#define MISSI_PAA 9
#define SET_CARD_EE 10
#define SET_MERCHANT_EE 11
#define SET_CARD_CA 12
#define SET_MERCHANT_CA 13
#define SET_GEOPOL_CA 14
#define SET_BRAND_CA 15
#define SET_ROOT_CA 16

struct CertificateValidityDate
    {
    struct casn self;
    struct casn utcTime;
    struct casn generalTime;
    };

void CertificateValidityDate(struct CertificateValidityDate *mine, ushort level);

struct Version
    {
    struct casn self;
    struct casn v1;
    struct casn v2;
    struct casn v3;
    };

void Version(struct Version *mine, ushort level);

int VersionConstraint(struct Version *);

struct Validity
    {
    struct casn self;
    struct CertificateValidityDate notBefore;
    struct CertificateValidityDate notAfter;
    };

void Validity(struct Validity *mine, ushort level);

struct SubjectPublicKeyInfo
    {
    struct casn self;
    struct AlgorithmIdentifier algorithm;
    struct casn subjectPublicKey;
    };

void SubjectPublicKeyInfo(struct SubjectPublicKeyInfo *mine, ushort level);

#define UniqueIdentifier casn

struct CertificateToBeSigned
    {
    struct casn self;
    struct Version version;
    struct casn serialNumber;
    struct AlgorithmIdentifier signature;
    struct Name issuer;
    struct Validity validity;
    struct Name subject;
    struct SubjectPublicKeyInfo subjectPublicKeyInfo;
    struct casn issuerUniqueID;
    struct casn subjectUniqueID;
    struct Extensions extensions;
    };

void CertificateToBeSigned(struct CertificateToBeSigned *mine, ushort level);

int CertificateToBeSignedConstraint(struct CertificateToBeSigned *);

struct Certificate
    {
    struct casn self;
    struct CertificateToBeSigned toBeSigned;
    struct AlgorithmIdentifier algorithm;
    struct casn signature;
    };

void Certificate(struct Certificate *mine, ushort level);

struct CertificatePair
    {
    struct casn self;
    struct Certificate forward;
    struct Certificate reverse;
    };

void CertificatePair(struct CertificatePair *mine, ushort level);

struct CrossCertificates
    {
    struct casn self;
    struct Certificate certificate;
    };

void CrossCertificates(struct CrossCertificates *mine, ushort level);

struct ForwardCertificationPath
    {
    struct casn self;
    struct CrossCertificates crossCertificates;
    };

void ForwardCertificationPath(struct ForwardCertificationPath *mine, ushort level);

struct TheCACertificatesInCertificationPath
    {
    struct casn self;
    struct CertificatePair certificatePair;
    };

void TheCACertificatesInCertificationPath(struct TheCACertificatesInCertificationPath *mine, ushort level);

struct CertificationPath
    {
    struct casn self;
    struct Certificate userCertificate;
    struct TheCACertificatesInCertificationPath theCACertificates;
    };

void CertificationPath(struct CertificationPath *mine, ushort level);

struct Certificates
    {
    struct casn self;
    struct Certificate certificate;
    struct ForwardCertificationPath certificationPath;
    };

void Certificates(struct Certificates *mine, ushort level);

#endif /* certificate_h */
