#ifndef _roa_h
#include "roa.h"
#endif

void ROA(struct ROA *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    ContentTableInROA(&mine->contentType, level);
    ContentTableDefined(&mine->content, level);
    mine->content.self.tag = 0xA0;
    mine->content.self.flags |= ASN_EXPLICIT_FLAG;
    mine->content.self.flags |= ASN_LAST_FLAG;
    }

void ContentTableInROA(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(2, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"1";
    tcasnp->lth = 1;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.7.2");
    tcasnp->level = level;
    }

void ContentTableDefined(struct ContentTableDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    SignedData(&mine->content, level);
    mine->content.self.flags |= ASN_LAST_FLAG;
    }

void SignedData(struct SignedData *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CMSVersion(&mine->version, level);
    DigestAlgorithmIdentifiers(&mine->digestAlgorithms, level);
    EncapsulatedContentInfo(&mine->encapContentInfo, level);
    CertificateSet(&mine->certificates, level);
    mine->certificates.self.tag = 0xA0;
    mine->certificates.self.flags |= ASN_OPTIONAL_FLAG;
    RevocationInfoChoices(&mine->crls, level);
    mine->crls.self.tag = 0xA1;
    mine->crls.self.flags |= ASN_OPTIONAL_FLAG;
    SignerInfos(&mine->signerInfos, level);
    mine->signerInfos.self.flags |= ASN_LAST_FLAG;
    }

void CMSVersion(struct CMSVersion *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_INTEGER);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->v0, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v0, (ulong)0);
    tagged_constructor(&mine->v1, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v1, (ulong)1);
    tagged_constructor(&mine->v3, level, ASN_INTEGER, 0x104);
    _write_casn_num(&mine->v3, (ulong)3);
    mine->v3.flags |= ASN_LAST_FLAG;
    }

int CMSVersionConstraint(struct CMSVersion *casnp)
    {
    long val;
    if (read_casn_num((struct casn *)casnp, &val) < 0) return 0;
    if (!diff_casn(&casnp->self, &casnp->v3) ||
        val == 3) return 1;
    return 0;
    }

void DigestAlgorithmIdentifiers(struct DigestAlgorithmIdentifiers *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    AlgorithmIdentifier(&mine->digestAlgorithmIdentifier, level);
    mine->digestAlgorithmIdentifier.self.flags |= ASN_LAST_FLAG;
    }

void CertificateSet(struct CertificateSet *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 1;
    Certificate(&mine->certificate, level);
    mine->certificate.self.flags |= ASN_LAST_FLAG;
    }

void CertificateChoices(struct CertificateChoices *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    Certificate(&mine->certificate, level);
    mine->certificate.self.flags |= ASN_LAST_FLAG;
    }

void RevocationInfoChoices(struct RevocationInfoChoices *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    RevocationInfoChoice(&mine->revocationInfoChoice, level);
    mine->revocationInfoChoice.self.flags |= ASN_LAST_FLAG;
    }

void RevocationInfoChoice(struct RevocationInfoChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    CertificateList(&mine->crl, level);
    OtherRevocationInfoFormat(&mine->other, level);
    mine->other.self.tag = 0xA1;
    mine->other.self.flags |= ASN_LAST_FLAG;
    }

void OtherRevocationInfoFormat(struct OtherRevocationInfoFormat *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->otherRevInfoFormat, level, ASN_OBJ_ID);
    simple_constructor(&mine->otherRevInfo, level, ASN_ANY);
    mine->otherRevInfo.flags |= ASN_LAST_FLAG;
    }

void CertificateList(struct CertificateList *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    TBSCertList(&mine->tbsCertList, level);
    AlgorithmIdentifier(&mine->signatureAlgorithm, level);
    simple_constructor(&mine->signatureValue, level, ASN_BITSTRING);
    mine->signatureValue.flags |= ASN_LAST_FLAG;
    }

void TBSCertList(struct TBSCertList *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Version(&mine->version, level);
    mine->version.self.flags |= ASN_OPTIONAL_FLAG;
    AlgorithmIdentifier(&mine->signature, level);
    Name(&mine->issuer, level);
    Time(&mine->thisUpdate, level);
    Time(&mine->nextUpdate, level);
    mine->nextUpdate.self.flags |= ASN_OPTIONAL_FLAG;
    RevokedCertificatesInTBSCertList(&mine->revokedCertificates, level);
    mine->revokedCertificates.self.flags |= ASN_OPTIONAL_FLAG;
    Extensions(&mine->crlExtensions, level);
    mine->crlExtensions.self.tag = 0xA0;
    mine->crlExtensions.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    mine->crlExtensions.self.flags |= ASN_LAST_FLAG;
    }

void RevokedCertificatesInTBSCertList(struct RevokedCertificatesInTBSCertList *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    SequenceInRevokedCertificatesInTBSCertList(&mine->sequenceInRevokedCertificatesInTBSCertList, level);
    mine->sequenceInRevokedCertificatesInTBSCertList.self.flags |= ASN_LAST_FLAG;
    }

void SequenceInRevokedCertificatesInTBSCertList(struct SequenceInRevokedCertificatesInTBSCertList *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->userCertificate, level, ASN_INTEGER);
    Time(&mine->revocationDate, level);
    Extensions(&mine->crlEntryExtensions, level);
    mine->crlEntryExtensions.self.flags |= ASN_OPTIONAL_FLAG;
    mine->crlEntryExtensions.self.flags |= ASN_LAST_FLAG;
    }

void Time(struct Time *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->utcTime, level, ASN_UTCTIME);
    simple_constructor(&mine->generalTime, level, ASN_GENTIME);
    mine->generalTime.flags |= ASN_LAST_FLAG;
    }

void SignerInfos(struct SignerInfos *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 1;
    SignerInfo(&mine->signerInfo, level);
    mine->signerInfo.self.flags |= ASN_LAST_FLAG;
    }

void EncapsulatedContentInfo(struct EncapsulatedContentInfo *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    EContentTableInEncapsulatedContentInfo(&mine->eContentType, level);
    EContentTableDefined(&mine->eContent, level);
    mine->eContent.self.tag = 0xA0;
    mine->eContent.self.type = 0x124;
    mine->eContent.self.flags |= ASN_EXPLICIT_FLAG;
    mine->eContent.self.flags |= ASN_LAST_FLAG;
    }

void EContentTableInEncapsulatedContentInfo(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(2, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"1";
    tcasnp->lth = 1;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.9.16.1.24");
    tcasnp->level = level;
    }

void EContentTableDefined(struct EContentTableDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    RouteOriginAttestation(&mine->roa, level);
    mine->roa.self.flags |= ASN_LAST_FLAG;
    }

void RouteOriginAttestation(struct RouteOriginAttestation *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    tagged_constructor(&mine->version, level, ASN_INTEGER, 0x80);
    mine->version.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->version.ptr = (struct casn *)((long)0);
    simple_constructor(&mine->asID, level, ASN_INTEGER);
    ROAIPAddrBlocks(&mine->ipAddrBlocks, level);
    mine->ipAddrBlocks.self.flags |= ASN_LAST_FLAG;
    }

void ROAIPAddrBlocks(struct ROAIPAddrBlocks *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    ROAIPAddressFamily(&mine->rOAIPAddressFamily, level);
    mine->rOAIPAddressFamily.self.flags |= ASN_LAST_FLAG;
    }

void ROAIPAddressFamily(struct ROAIPAddressFamily *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->addressFamily, level, ASN_OCTETSTRING);
    mine->addressFamily.min = 2;
    mine->addressFamily.max = 3;
    AddressesInROAIPAddressFamily(&mine->addresses, level);
    mine->addresses.self.flags |= ASN_LAST_FLAG;
    }

void AddressesInROAIPAddressFamily(struct AddressesInROAIPAddressFamily *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    simple_constructor(&mine->iPAddress, level, ASN_BITSTRING);
    mine->iPAddress.flags |= ASN_LAST_FLAG;
    }

void SignerInfo(struct SignerInfo *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CMSVersion(&mine->version, level);
    SignerIdentifier(&mine->sid, level);
    AlgorithmIdentifier(&mine->digestAlgorithm, level);
    SignedAttributes(&mine->signedAttrs, level);
    mine->signedAttrs.self.tag = 0xA0;
    mine->signedAttrs.self.flags |= ASN_OPTIONAL_FLAG;
    AlgorithmIdentifier(&mine->signatureAlgorithm, level);
    simple_constructor(&mine->signature, level, ASN_OCTETSTRING);
    UnsignedAttributes(&mine->unsignedAttrs, level);
    mine->unsignedAttrs.self.tag = 0xA1;
    mine->unsignedAttrs.self.flags |= ASN_OPTIONAL_FLAG;
    mine->unsignedAttrs.self.flags |= ASN_LAST_FLAG;
    }

void SignedAttributes(struct SignedAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 2147483647;
    Attribute(&mine->attribute, level);
    mine->attribute.self.flags |= ASN_LAST_FLAG;
    }

void UnsignedAttributes(struct UnsignedAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 2147483647;
    Attribute(&mine->attribute, level);
    mine->attribute.self.flags |= ASN_LAST_FLAG;
    }

void SignerIdentifier(struct SignerIdentifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    IssuerAndSerialNumber(&mine->issuerAndSerialNumber, level);
    tagged_constructor(&mine->subjectKeyIdentifier, level, ASN_OCTETSTRING, 0x80);
    mine->subjectKeyIdentifier.flags |= ASN_LAST_FLAG;
    }

void IssuerAndSerialNumber(struct IssuerAndSerialNumber *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Name(&mine->issuer, level);
    simple_constructor(&mine->serialNumber, level, ASN_INTEGER);
    mine->serialNumber.flags |= ASN_LAST_FLAG;
    }

