#ifndef _roa_h
#define _roa_h

#ifndef _casn_h
#include "casn.h"
#endif
#ifndef _Algorithms_h
#include "Algorithms.h"
#endif
#ifndef _extensions_h
#include "extensions.h"
#endif
#ifndef _certificate_h
#include "certificate.h"
#endif
#ifndef _name_h
#include "name.h"
#endif
#define id_signedData "1.2.840.113549.1.7.2"
#define us "840"
#define rsadsi "113549"
#define pkcs "1"
#define pkcs7 "7"
#define id_sha256 "2.16.840.1.101.3.4.2.1"
#define country "16"
#define organization "1"
#define us_government "101"
#define id_smime "1.2.840.113549.1.9.16"
#define pkcs9 "9"
#define id_ct "1.2.840.113549.1.9.16.1"
#define routeOriginAttestation "1.2.840.113549.1.9.16.1.24"

#define IPAddress casn

struct AddressesInROAIPAddressFamily
    {
    struct casn self;
    struct casn iPAddress;
    };

void AddressesInROAIPAddressFamily(struct AddressesInROAIPAddressFamily *mine, ushort level);

#define CertificateSerialNumber casn

struct Time
    {
    struct casn self;
    struct casn utcTime;
    struct casn generalTime;
    };

void Time(struct Time *mine, ushort level);

struct ROAIPAddressFamily
    {
    struct casn self;
    struct casn addressFamily;
    struct AddressesInROAIPAddressFamily addresses;
    };

void ROAIPAddressFamily(struct ROAIPAddressFamily *mine, ushort level);

struct SequenceInRevokedCertificatesInTBSCertList
    {
    struct casn self;
    struct casn userCertificate;
    struct Time revocationDate;
    struct Extensions crlEntryExtensions;
    };

void SequenceInRevokedCertificatesInTBSCertList(struct SequenceInRevokedCertificatesInTBSCertList *mine, ushort level);

#define ASID casn

struct ROAIPAddrBlocks
    {
    struct casn self;
    struct ROAIPAddressFamily rOAIPAddressFamily;
    };

void ROAIPAddrBlocks(struct ROAIPAddrBlocks *mine, ushort level);

struct RouteOriginAttestation
    {
    struct casn self;
    struct casn version;
    struct casn asID;
    struct ROAIPAddrBlocks ipAddrBlocks;
    };

void RouteOriginAttestation(struct RouteOriginAttestation *mine, ushort level);

#define SubjectKeyIdentifier casn

struct RevokedCertificatesInTBSCertList
    {
    struct casn self;
    struct SequenceInRevokedCertificatesInTBSCertList sequenceInRevokedCertificatesInTBSCertList;
    };

void RevokedCertificatesInTBSCertList(struct RevokedCertificatesInTBSCertList *mine, ushort level);

struct OtherRevocationInfoFormat
    {
    struct casn self;
    struct casn otherRevInfoFormat;
    struct casn otherRevInfo;
    };

void OtherRevocationInfoFormat(struct OtherRevocationInfoFormat *mine, ushort level);

struct TBSCertList
    {
    struct casn self;
    struct Version version;
    struct AlgorithmIdentifier signature;
    struct Name issuer;
    struct Time thisUpdate;
    struct Time nextUpdate;
    struct RevokedCertificatesInTBSCertList revokedCertificates;
    struct Extensions crlExtensions;
    };

void TBSCertList(struct TBSCertList *mine, ushort level);

struct IssuerAndSerialNumber
    {
    struct casn self;
    struct Name issuer;
    struct casn serialNumber;
    };

void IssuerAndSerialNumber(struct IssuerAndSerialNumber *mine, ushort level);

void EContentTableInEncapsulatedContentInfo(struct casn *mine, ushort level);

struct EContentTableDefined
    {
    struct casn self;
    struct RouteOriginAttestation roa;
    };

void EContentTableDefined(struct EContentTableDefined *mine, ushort level);

struct CMSVersion
    {
    struct casn self;
    struct casn v0;
    struct casn v1;
    struct casn v3;
    };

void CMSVersion(struct CMSVersion *mine, ushort level);

int CMSVersionConstraint(struct CMSVersion *);

struct CertificateList
    {
    struct casn self;
    struct TBSCertList tbsCertList;
    struct AlgorithmIdentifier signatureAlgorithm;
    struct casn signatureValue;
    };

void CertificateList(struct CertificateList *mine, ushort level);

struct SignedAttributes
    {
    struct casn self;
    struct Attribute attribute;
    };

void SignedAttributes(struct SignedAttributes *mine, ushort level);

struct UnsignedAttributes
    {
    struct casn self;
    struct Attribute attribute;
    };

void UnsignedAttributes(struct UnsignedAttributes *mine, ushort level);

struct SignerIdentifier
    {
    struct casn self;
    struct IssuerAndSerialNumber issuerAndSerialNumber;
    struct casn subjectKeyIdentifier;
    };

void SignerIdentifier(struct SignerIdentifier *mine, ushort level);

#define SignatureValue casn

#define DigestAlgorithmIdentifier AlgorithmIdentifier

#define SignatureAlgorithmIdentifier AlgorithmIdentifier

#define ContentType casn

struct RevocationInfoChoice
    {
    struct casn self;
    struct CertificateList crl;
    struct OtherRevocationInfoFormat other;
    };

void RevocationInfoChoice(struct RevocationInfoChoice *mine, ushort level);

struct SignerInfo
    {
    struct casn self;
    struct CMSVersion version;
    struct SignerIdentifier sid;
    struct AlgorithmIdentifier digestAlgorithm;
    struct SignedAttributes signedAttrs;
    struct AlgorithmIdentifier signatureAlgorithm;
    struct casn signature;
    struct UnsignedAttributes unsignedAttrs;
    };

void SignerInfo(struct SignerInfo *mine, ushort level);

struct DigestAlgorithmIdentifiers
    {
    struct casn self;
    struct AlgorithmIdentifier digestAlgorithmIdentifier;
    };

void DigestAlgorithmIdentifiers(struct DigestAlgorithmIdentifiers *mine, ushort level);

struct CertificateSet
    {
    struct casn self;
    struct Certificate certificate;
    };

void CertificateSet(struct CertificateSet *mine, ushort level);

struct RevocationInfoChoices
    {
    struct casn self;
    struct RevocationInfoChoice revocationInfoChoice;
    };

void RevocationInfoChoices(struct RevocationInfoChoices *mine, ushort level);

struct SignerInfos
    {
    struct casn self;
    struct SignerInfo signerInfo;
    };

void SignerInfos(struct SignerInfos *mine, ushort level);

struct EncapsulatedContentInfo
    {
    struct casn self;
    struct casn eContentType;
    struct EContentTableDefined eContent;
    };

void EncapsulatedContentInfo(struct EncapsulatedContentInfo *mine, ushort level);

struct SignedData
    {
    struct casn self;
    struct CMSVersion version;
    struct DigestAlgorithmIdentifiers digestAlgorithms;
    struct EncapsulatedContentInfo encapContentInfo;
    struct CertificateSet certificates;
    struct RevocationInfoChoices crls;
    struct SignerInfos signerInfos;
    };

void SignedData(struct SignedData *mine, ushort level);

void ContentTableInROA(struct casn *mine, ushort level);

struct ContentTableDefined
    {
    struct casn self;
    struct SignedData content;
    };

void ContentTableDefined(struct ContentTableDefined *mine, ushort level);

struct ROA
    {
    struct casn self;
    struct casn contentType;
    struct ContentTableDefined content;
    };

void ROA(struct ROA *mine, ushort level);

struct CertificateChoices
    {
    struct casn self;
    struct Certificate certificate;
    };

void CertificateChoices(struct CertificateChoices *mine, ushort level);

#endif /* roa_h */
