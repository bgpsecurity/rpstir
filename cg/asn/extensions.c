#ifndef _extensions_h
#include "extensions.h"
#endif

void Extensions(struct Extensions *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    Extension(&mine->extension, level);
    mine->extension.self.flags |= ASN_LAST_FLAG;
    }

void Extension(struct Extension *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    ExtensionSetInExtension(&mine->extnID, level);
    simple_constructor(&mine->critical, level, ASN_BOOLEAN);
    mine->critical.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    ExtensionSetDefined(&mine->extnValue, level);
    mine->extnValue.self.tag = ASN_OCTETSTRING;
    mine->extnValue.self.type = 0x124;
    mine->extnValue.self.flags |= ASN_LAST_FLAG;
    }

void ExtensionSetInExtension(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(25, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"2";
    tcasnp->lth = 24;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.9");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.14");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.15");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.16");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.17");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.18");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.19");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.30");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.32");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.33");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.36");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.31");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.35");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.37");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.3");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.5");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.1.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.1.7");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.1.8");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.1.9");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void ExtensionSetDefined(struct ExtensionSetDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    SubjectDirectoryAttributes(&mine->subjectDirectoryAttributes, level);
    simple_constructor(&mine->subjectKeyIdentifier, level, ASN_OCTETSTRING);
    KeyUsage(&mine->keyUsage, level);
    PrivateKeyUsagePeriod(&mine->privateKeyUsagePeriod, level);
    GeneralNames(&mine->subjectAltName, level);
    GeneralNames(&mine->issuerAltName, level);
    BasicConstraints(&mine->basicConstraints, level);
    NameConstraints(&mine->nameConstraints, level);
    CertificatePolicies(&mine->certificatePolicies, level);
    PolicyMappings(&mine->policyMappings, level);
    PolicyConstraints(&mine->policyConstraints, level);
    CRLDistributionPoints(&mine->cRLDistributionPoints, level);
    AuthorityKeyId(&mine->authKeyId, level);
    ExtKeyUsageSyntax(&mine->extKeyUsage, level);
    CertificateType(&mine->certificateType, level);
    MerchantData(&mine->merchantData, level);
    simple_constructor(&mine->cardCertRequired, level, ASN_BOOLEAN);
    Tunneling(&mine->tunneling, level);
    SetExtensions(&mine->setExtensions, level);
    AuthorityInfoAccessSyntax(&mine->authorityInfoAccess, level);
    SBGPIpAddrBlock(&mine->ipAddressBlock, level);
    SBGPASNum(&mine->autonomousSysNum, level);
    RouterIdentifier(&mine->routerId, level);
    simple_constructor(&mine->other, level, ASN_NOTASN1);
    mine->other.flags |= ASN_LAST_FLAG;
    }

void AuthorityKeyId(struct AuthorityKeyId *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    tagged_constructor(&mine->keyIdentifier, level, ASN_OCTETSTRING, 0x80);
    mine->keyIdentifier.flags |= ASN_OPTIONAL_FLAG;
    GeneralNames(&mine->certIssuer, level);
    mine->certIssuer.self.tag = 0xA1;
    mine->certIssuer.self.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->certSerialNumber, level, ASN_INTEGER, 0x82);
    mine->certSerialNumber.flags |= ASN_OPTIONAL_FLAG;
    mine->certSerialNumber.flags |= ASN_LAST_FLAG;
    }

void KeyUsage(struct KeyUsage *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_BITSTRING);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->digitalSignature, level, ASN_BITSTRING, 0x104);
    mine->digitalSignature.min = 0;
    tagged_constructor(&mine->nonRepudiation, level, ASN_BITSTRING, 0x104);
    mine->nonRepudiation.min = 1;
    tagged_constructor(&mine->keyEncipherment, level, ASN_BITSTRING, 0x104);
    mine->keyEncipherment.min = 2;
    tagged_constructor(&mine->dataEncipherment, level, ASN_BITSTRING, 0x104);
    mine->dataEncipherment.min = 3;
    tagged_constructor(&mine->keyAgreement, level, ASN_BITSTRING, 0x104);
    mine->keyAgreement.min = 4;
    tagged_constructor(&mine->keyCertSign, level, ASN_BITSTRING, 0x104);
    mine->keyCertSign.min = 5;
    tagged_constructor(&mine->cRLSign, level, ASN_BITSTRING, 0x104);
    mine->cRLSign.min = 6;
    tagged_constructor(&mine->encipherOnly, level, ASN_BITSTRING, 0x104);
    mine->encipherOnly.min = 7;
    tagged_constructor(&mine->decipherOnly, level, ASN_BITSTRING, 0x104);
    mine->decipherOnly.min = 8;
    mine->decipherOnly.flags |= ASN_LAST_FLAG;
    }

void PrivateKeyUsagePeriod(struct PrivateKeyUsagePeriod *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    tagged_constructor(&mine->notBefore, level, ASN_GENTIME, 0x80);
    mine->notBefore.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->notAfter, level, ASN_GENTIME, 0x81);
    mine->notAfter.flags |= ASN_OPTIONAL_FLAG;
    mine->notAfter.flags |= ASN_LAST_FLAG;
    }

void CertificatePolicies(struct CertificatePolicies *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    PolicyInformation(&mine->policyInformation, level);
    mine->policyInformation.self.flags |= ASN_LAST_FLAG;
    }

void PolicyInformation(struct PolicyInformation *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->policyIdentifier, level, ASN_OBJ_ID);
    PolicyQualifiersInPolicyInformation(&mine->policyQualifiers, level);
    mine->policyQualifiers.self.flags |= ASN_OPTIONAL_FLAG;
    mine->policyQualifiers.self.flags |= ASN_LAST_FLAG;
    }

void PolicyQualifiersInPolicyInformation(struct PolicyQualifiersInPolicyInformation *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    PolicyQualifierInfo(&mine->policyQualifierInfo, level);
    mine->policyQualifierInfo.self.flags |= ASN_LAST_FLAG;
    }

void PolicyQualifierInfo(struct PolicyQualifierInfo *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    PolicyQualifierInfoSetInPolicyQualifierInfo(&mine->policyQualifierId, level);
    PolicyQualifierInfoSetDefined(&mine->qualifier, level);
    mine->qualifier.self.flags |= ASN_OPTIONAL_FLAG;
    mine->qualifier.self.flags |= ASN_LAST_FLAG;
    }

void PolicyQualifierInfoSetInPolicyQualifierInfo(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(5, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"1";
    tcasnp->lth = 4;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.2.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.5.5.7.2.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.23.42.7.6");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void PolicyQualifierInfoSetDefined(struct PolicyQualifierInfoSetDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    simple_constructor(&mine->cPSuri, level, ASN_IA5_STRING);
    UserNotice(&mine->userNotice, level);
    SetPolicyQualifier(&mine->setQualifier, level);
    simple_constructor(&mine->any, level, ASN_ANY);
    mine->any.flags |= ASN_LAST_FLAG;
    }

void UserNotice(struct UserNotice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    NoticeReference(&mine->noticeRef, level);
    mine->noticeRef.self.flags |= ASN_OPTIONAL_FLAG;
    DisplayText(&mine->explicitText, level);
    mine->explicitText.self.flags |= ASN_OPTIONAL_FLAG;
    mine->explicitText.self.flags |= ASN_LAST_FLAG;
    }

void NoticeReference(struct NoticeReference *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->organization, level, ASN_IA5_STRING);
    NoticeNumbersInNoticeReference(&mine->noticeNumbers, level);
    mine->noticeNumbers.self.flags |= ASN_LAST_FLAG;
    }

void NoticeNumbersInNoticeReference(struct NoticeNumbersInNoticeReference *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    simple_constructor(&mine->array, level, ASN_INTEGER);
    mine->array.flags |= ASN_LAST_FLAG;
    }

void DisplayText(struct DisplayText *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void SetPolicyQualifier(struct SetPolicyQualifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    SETQualifier(&mine->rootQualifier, level);
    AdditionalPolicies(&mine->additionalPolicies, level);
    mine->additionalPolicies.self.flags |= ASN_OPTIONAL_FLAG;
    mine->additionalPolicies.self.flags |= ASN_LAST_FLAG;
    }

void AdditionalPolicies(struct AdditionalPolicies *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 3;
    AdditionalPolicy(&mine->additionalPolicy, level);
    mine->additionalPolicy.self.flags |= ASN_LAST_FLAG;
    }

void AdditionalPolicy(struct AdditionalPolicy *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->policyOID, level, ASN_OBJ_ID);
    mine->policyOID.flags |= ASN_OPTIONAL_FLAG;
    SETQualifier(&mine->policyQualifier, level);
    mine->policyQualifier.self.flags |= ASN_OPTIONAL_FLAG;
    CertificateType(&mine->policyAddedBy, level);
    mine->policyAddedBy.self.flags |= ASN_LAST_FLAG;
    }

void PolicyMappings(struct PolicyMappings *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    SequenceInPolicyMappings(&mine->sequenceInPolicyMappings, level);
    mine->sequenceInPolicyMappings.self.flags |= ASN_LAST_FLAG;
    }

void SequenceInPolicyMappings(struct SequenceInPolicyMappings *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->issuerDomainPolicy, level, ASN_OBJ_ID);
    simple_constructor(&mine->subjectDomainPolicy, level, ASN_OBJ_ID);
    mine->subjectDomainPolicy.flags |= ASN_LAST_FLAG;
    }

void GeneralNames(struct GeneralNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    GeneralName(&mine->generalName, level);
    mine->generalName.self.flags |= ASN_LAST_FLAG;
    }

void GeneralName(struct GeneralName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    Other_name(&mine->otherName, level);
    mine->otherName.self.tag = 0xA0;
    tagged_constructor(&mine->rfc822Name, level, ASN_IA5_STRING, 0x81);
    tagged_constructor(&mine->dNSName, level, ASN_IA5_STRING, 0x82);
    ORAddress(&mine->x400Address, level);
    mine->x400Address.self.tag = 0xA3;
    Name(&mine->directoryName, level);
    mine->directoryName.self.tag = 0xA4;
    EDIPartyName(&mine->ediPartyName, level);
    mine->ediPartyName.self.tag = 0xA5;
    tagged_constructor(&mine->url, level, ASN_IA5_STRING, 0x86);
    tagged_constructor(&mine->iPAddress, level, ASN_OCTETSTRING, 0x87);
    tagged_constructor(&mine->registeredID, level, ASN_OBJ_ID, 0x88);
    mine->registeredID.flags |= ASN_LAST_FLAG;
    }

void Other_name(struct Other_name *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Other_nameTableInOther_name(&mine->type_id, level);
    Other_nameTableDefined(&mine->value, level);
    mine->value.self.flags |= ASN_LAST_FLAG;
    }

void Other_nameTableInOther_name(struct casn *mine, ushort level)
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
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void Other_nameTableDefined(struct Other_nameTableDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    simple_constructor(&mine->any, level, ASN_ANY);
    mine->any.flags |= ASN_LAST_FLAG;
    }

void EDIPartyName(struct EDIPartyName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    DirectoryString(&mine->nameAssigner, level);
    mine->nameAssigner.self.tag = 0xA0;
    mine->nameAssigner.self.flags |= ASN_OPTIONAL_FLAG;
    DirectoryString(&mine->partyName, level);
    mine->partyName.self.tag = 0xA1;
    mine->partyName.self.flags |= ASN_LAST_FLAG;
    }

void SubjectDirectoryAttributes(struct SubjectDirectoryAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    Attribute(&mine->attribute, level);
    mine->attribute.self.flags |= ASN_LAST_FLAG;
    }

void Attribute(struct Attribute *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    AttributeTableInAttribute(&mine->type, level);
    ValuesInAttribute(&mine->values, level);
    mine->values.self.min = 1;
    mine->values.self.max = 20;
    mine->values.self.flags |= ASN_LAST_FLAG;
    }

void ValuesInAttribute(struct ValuesInAttribute *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    AttributeTableDefined(&mine->array, level);
    mine->array.self.flags |= ASN_LAST_FLAG;
    }

void AttributeTableInAttribute(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(2, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"10";
    tcasnp->lth = 1;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void AttributeTableDefined(struct AttributeTableDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    simple_constructor(&mine->any, level, ASN_ANY);
    mine->any.flags |= ASN_LAST_FLAG;
    }

void BasicConstraints(struct BasicConstraints *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->cA, level, ASN_BOOLEAN);
    mine->cA.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    simple_constructor(&mine->pathLenConstraint, level, ASN_INTEGER);
    mine->pathLenConstraint.flags |= ASN_OPTIONAL_FLAG;
    mine->pathLenConstraint.flags |= ASN_LAST_FLAG;
    }

void NameConstraints(struct NameConstraints *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    GeneralSubtrees(&mine->permittedSubtrees, level);
    mine->permittedSubtrees.self.tag = 0xA0;
    mine->permittedSubtrees.self.flags |= ASN_OPTIONAL_FLAG;
    GeneralSubtrees(&mine->excludedSubtrees, level);
    mine->excludedSubtrees.self.tag = 0xA1;
    mine->excludedSubtrees.self.flags |= ASN_OPTIONAL_FLAG;
    mine->excludedSubtrees.self.flags |= ASN_LAST_FLAG;
    }

void GeneralSubtrees(struct GeneralSubtrees *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    GeneralSubtree(&mine->generalSubtree, level);
    mine->generalSubtree.self.flags |= ASN_LAST_FLAG;
    }

void GeneralSubtree(struct GeneralSubtree *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    GeneralName(&mine->base, level);
    tagged_constructor(&mine->minimum, level, ASN_INTEGER, 0x80);
    mine->minimum.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->minimum.ptr = (struct casn *)((long)0);
    tagged_constructor(&mine->maximum, level, ASN_INTEGER, 0x81);
    mine->maximum.flags |= ASN_OPTIONAL_FLAG;
    mine->maximum.flags |= ASN_LAST_FLAG;
    }

void PolicyConstraints(struct PolicyConstraints *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    tagged_constructor(&mine->requireExplicitPolicy, level, ASN_INTEGER, 0x80);
    mine->requireExplicitPolicy.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->inhibitPolicyMapping, level, ASN_INTEGER, 0x81);
    mine->inhibitPolicyMapping.flags |= ASN_OPTIONAL_FLAG;
    mine->inhibitPolicyMapping.flags |= ASN_LAST_FLAG;
    }

void CRLDistributionPoints(struct CRLDistributionPoints *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    DistributionPoint(&mine->distributionPoint, level);
    mine->distributionPoint.self.flags |= ASN_LAST_FLAG;
    }

void DistributionPoint(struct DistributionPoint *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    DistributionPointName(&mine->distributionPoint, level);
    mine->distributionPoint.self.tag = 0xA0;
    mine->distributionPoint.self.flags |= ASN_OPTIONAL_FLAG;
    ReasonFlags(&mine->reasons, level);
    mine->reasons.self.tag = 0x81;
    mine->reasons.self.flags |= ASN_OPTIONAL_FLAG;
    GeneralNames(&mine->cRLIssuer, level);
    mine->cRLIssuer.self.tag = 0xA2;
    mine->cRLIssuer.self.flags |= ASN_OPTIONAL_FLAG;
    mine->cRLIssuer.self.flags |= ASN_LAST_FLAG;
    }

void DistributionPointName(struct DistributionPointName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    GeneralNames(&mine->fullName, level);
    mine->fullName.self.tag = 0xA0;
    RelativeDistinguishedName(&mine->nameRelativeToCRLIssuer, level);
    mine->nameRelativeToCRLIssuer.self.tag = 0xA1;
    mine->nameRelativeToCRLIssuer.self.flags |= ASN_LAST_FLAG;
    }

void ReasonFlags(struct ReasonFlags *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_BITSTRING);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->unused, level, ASN_BITSTRING, 0x104);
    mine->unused.min = 0;
    tagged_constructor(&mine->keyCompromise, level, ASN_BITSTRING, 0x104);
    mine->keyCompromise.min = 1;
    tagged_constructor(&mine->caCompromise, level, ASN_BITSTRING, 0x104);
    mine->caCompromise.min = 2;
    tagged_constructor(&mine->affiliationChanged, level, ASN_BITSTRING, 0x104);
    mine->affiliationChanged.min = 3;
    tagged_constructor(&mine->superseded, level, ASN_BITSTRING, 0x104);
    mine->superseded.min = 4;
    tagged_constructor(&mine->cessationOfOperation, level, ASN_BITSTRING, 0x104);
    mine->cessationOfOperation.min = 5;
    tagged_constructor(&mine->certificateHold, level, ASN_BITSTRING, 0x104);
    mine->certificateHold.min = 6;
    mine->certificateHold.flags |= ASN_LAST_FLAG;
    }

void CrlExtensions(struct CrlExtensions *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    CRLExtension(&mine->cRLExtension, level);
    mine->cRLExtension.self.flags |= ASN_LAST_FLAG;
    }

void CRLExtension(struct CRLExtension *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CRLExtensionSetInCRLExtension(&mine->extnID, level);
    simple_constructor(&mine->critical, level, ASN_BOOLEAN);
    mine->critical.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    CRLExtensionSetDefined(&mine->extnValue, level);
    mine->extnValue.self.tag = ASN_OCTETSTRING;
    mine->extnValue.self.type = 0x124;
    mine->extnValue.self.flags |= ASN_LAST_FLAG;
    }

void CRLExtensionSetInCRLExtension(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(7, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"2";
    tcasnp->lth = 6;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.35");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.18");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.20");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.28");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.27");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void CRLExtensionSetDefined(struct CRLExtensionSetDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    AuthorityKeyId(&mine->authKeyId, level);
    GeneralNames(&mine->issuerAltName, level);
    simple_constructor(&mine->cRLNumber, level, ASN_INTEGER);
    IssuingDistPoint(&mine->issuingDistributionPoint, level);
    simple_constructor(&mine->deltaCRLIndicator, level, ASN_INTEGER);
    simple_constructor(&mine->other, level, ASN_NOTASN1);
    mine->other.flags |= ASN_LAST_FLAG;
    }

void IssuingDistPoint(struct IssuingDistPoint *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    DistributionPointName(&mine->distributionPoint, level);
    mine->distributionPoint.self.tag = 0xA0;
    mine->distributionPoint.self.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->onlyContainsUserCerts, level, ASN_BOOLEAN, 0x81);
    mine->onlyContainsUserCerts.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    tagged_constructor(&mine->onlyContainsCACerts, level, ASN_BOOLEAN, 0x82);
    mine->onlyContainsCACerts.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    ReasonFlags(&mine->onlySomeReasons, level);
    mine->onlySomeReasons.self.tag = 0x83;
    mine->onlySomeReasons.self.flags |= ASN_OPTIONAL_FLAG;
    tagged_constructor(&mine->indirectCRL, level, ASN_BOOLEAN, 0x84);
    mine->indirectCRL.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->indirectCRL.flags |= ASN_LAST_FLAG;
    }

void CrlEntryExtensions(struct CrlEntryExtensions *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    CRLEntryExtension(&mine->cRLEntryExtension, level);
    mine->cRLEntryExtension.self.flags |= ASN_LAST_FLAG;
    }

void CRLEntryExtension(struct CRLEntryExtension *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CRLEntryExtensionSetInCRLEntryExtension(&mine->extnID, level);
    simple_constructor(&mine->critical, level, ASN_BOOLEAN);
    mine->critical.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    CRLEntryExtensionSetDefined(&mine->extnValue, level);
    mine->extnValue.self.tag = ASN_OCTETSTRING;
    mine->extnValue.self.type = 0x124;
    mine->extnValue.self.flags |= ASN_LAST_FLAG;
    }

void CRLEntryExtensionSetInCRLEntryExtension(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(6, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"2";
    tcasnp->lth = 5;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.21");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.24");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.23");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.29.29");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void CRLEntryExtensionSetDefined(struct CRLEntryExtensionSetDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    CRLReason(&mine->reasonCode, level);
    simple_constructor(&mine->invalidityDate, level, ASN_GENTIME);
    simple_constructor(&mine->instructionCode, level, ASN_OBJ_ID);
    GeneralNames(&mine->certificateIssuer, level);
    simple_constructor(&mine->other, level, ASN_NOTASN1);
    mine->other.flags |= ASN_LAST_FLAG;
    }

void CRLReason(struct CRLReason *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_ENUMERATED);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->unspecified, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->unspecified, (ulong)0);
    tagged_constructor(&mine->keyCompromised, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->keyCompromised, (ulong)1);
    tagged_constructor(&mine->caCompromised, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->caCompromised, (ulong)2);
    tagged_constructor(&mine->affiliationChanged, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->affiliationChanged, (ulong)3);
    tagged_constructor(&mine->superseded, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->superseded, (ulong)4);
    tagged_constructor(&mine->cessationOfOperation, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->cessationOfOperation, (ulong)5);
    tagged_constructor(&mine->certificateHold, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->certificateHold, (ulong)6);
    tagged_constructor(&mine->certHoldRelease, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->certHoldRelease, (ulong)7);
    tagged_constructor(&mine->removeFromCRL, level, ASN_ENUMERATED, 0x104);
    _write_casn_num(&mine->removeFromCRL, (ulong)8);
    mine->removeFromCRL.flags |= ASN_LAST_FLAG;
    }

void MerchantID(struct MerchantID *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 30;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 30;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void BIN(struct BIN *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_NUMERIC_STRING);
    mine->self.min = 6;
    mine->self.max = 6;
    }

void CountryCode(struct CountryCode *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_INTEGER);
    mine->self.min = 1;
    mine->self.max = 999;
    }

void Language(struct Language *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_VISIBLE_STRING);
    mine->self.min = 1;
    mine->self.max = 35;
    }

void CertificateType(struct CertificateType *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_BITSTRING);
    mine->self.flags |= ASN_ENUM_FLAG;
    tagged_constructor(&mine->card, level, ASN_BITSTRING, 0x104);
    mine->card.min = 0;
    tagged_constructor(&mine->mer, level, ASN_BITSTRING, 0x104);
    mine->mer.min = 1;
    tagged_constructor(&mine->pgwy, level, ASN_BITSTRING, 0x104);
    mine->pgwy.min = 2;
    tagged_constructor(&mine->cca, level, ASN_BITSTRING, 0x104);
    mine->cca.min = 3;
    tagged_constructor(&mine->mca, level, ASN_BITSTRING, 0x104);
    mine->mca.min = 4;
    tagged_constructor(&mine->pca, level, ASN_BITSTRING, 0x104);
    mine->pca.min = 5;
    tagged_constructor(&mine->gca, level, ASN_BITSTRING, 0x104);
    mine->gca.min = 6;
    tagged_constructor(&mine->bca, level, ASN_BITSTRING, 0x104);
    mine->bca.min = 7;
    tagged_constructor(&mine->rca, level, ASN_BITSTRING, 0x104);
    mine->rca.min = 8;
    tagged_constructor(&mine->acq, level, ASN_BITSTRING, 0x104);
    mine->acq.min = 9;
    mine->acq.flags |= ASN_LAST_FLAG;
    }

void MerchantData(struct MerchantData *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    MerchantID(&mine->merID, level);
    BIN(&mine->merAcquirerBIN, level);
    mine->merAcquirerBIN.self.min = 6;
    mine->merAcquirerBIN.self.max = 6;
    MerNameSeq(&mine->merNameSeq, level);
    CountryCode(&mine->merCountry, level);
    mine->merCountry.self.min = 1;
    mine->merCountry.self.max = 999;
    simple_constructor(&mine->merAuthFlag, level, ASN_BOOLEAN);
    mine->merAuthFlag.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->merAuthFlag.min = 1;
    mine->merAuthFlag.flags |= ASN_LAST_FLAG;
    }

void MerNameSeq(struct MerNameSeq *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 32;
    MerNames(&mine->merNames, level);
    mine->merNames.self.flags |= ASN_LAST_FLAG;
    }

void MerNames(struct MerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Language(&mine->language, level);
    mine->language.self.tag = 0x80;
    mine->language.self.min = 1;
    mine->language.self.max = 35;
    mine->language.self.flags |= ASN_OPTIONAL_FLAG;
    NameInMerNames(&mine->name, level);
    mine->name.self.tag = 0xA1;
    mine->name.self.flags |= ASN_EXPLICIT_FLAG;
    CityInMerNames(&mine->city, level);
    mine->city.self.tag = 0xA2;
    mine->city.self.flags |= ASN_EXPLICIT_FLAG;
    StateProvinceInMerNames(&mine->stateProvince, level);
    mine->stateProvince.self.tag = 0xA3;
    mine->stateProvince.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    PostalCodeInMerNames(&mine->postalCode, level);
    mine->postalCode.self.tag = 0xA4;
    mine->postalCode.self.flags |= ASN_OPTIONAL_FLAG | ASN_EXPLICIT_FLAG;
    CountryNameInMerNames(&mine->countryName, level);
    mine->countryName.self.tag = 0xA5;
    mine->countryName.self.flags |= ASN_EXPLICIT_FLAG;
    mine->countryName.self.flags |= ASN_LAST_FLAG;
    }

void NameInMerNames(struct NameInMerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 25;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 25;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void CityInMerNames(struct CityInMerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 50;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 50;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void StateProvinceInMerNames(struct StateProvinceInMerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 25;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 25;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void PostalCodeInMerNames(struct PostalCodeInMerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 14;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 14;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void CountryNameInMerNames(struct CountryNameInMerNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 50;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 50;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void Tunneling(struct Tunneling *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->tunneling, level, ASN_BOOLEAN);
    mine->tunneling.flags |= ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG;
    mine->tunneling.min = 1;
    TunnelAlg(&mine->tunnelAlgIDs, level);
    mine->tunnelAlgIDs.self.flags |= ASN_LAST_FLAG;
    }

void TunnelAlg(struct TunnelAlg *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    simple_constructor(&mine->iD, level, ASN_OBJ_ID);
    mine->iD.flags |= ASN_LAST_FLAG;
    }

void SetExtensions(struct SetExtensions *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    simple_constructor(&mine->iD, level, ASN_OBJ_ID);
    mine->iD.flags |= ASN_LAST_FLAG;
    }

void URL(struct URL *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_VISIBLE_STRING);
    mine->self.min = 1;
    mine->self.max = 512;
    }

void SETQualifier(struct SETQualifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    TerseStatementInSETQualifier(&mine->terseStatement, level);
    mine->terseStatement.self.flags |= ASN_OPTIONAL_FLAG;
    URL(&mine->policyURL, level);
    mine->policyURL.self.tag = 0x80;
    mine->policyURL.self.min = 1;
    mine->policyURL.self.max = 512;
    mine->policyURL.self.flags |= ASN_OPTIONAL_FLAG;
    URL(&mine->policyEmail, level);
    mine->policyEmail.self.tag = 0x81;
    mine->policyEmail.self.min = 1;
    mine->policyEmail.self.max = 512;
    mine->policyEmail.self.flags |= ASN_OPTIONAL_FLAG;
    mine->policyEmail.self.flags |= ASN_LAST_FLAG;
    }

void TerseStatementInSETQualifier(struct TerseStatementInSETQualifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->visibleString, level, ASN_VISIBLE_STRING);
    mine->visibleString.min = 1;
    mine->visibleString.max = 2048;
    simple_constructor(&mine->bmpString, level, ASN_BMP_STRING);
    mine->bmpString.min = 1;
    mine->bmpString.max = 2048;
    mine->bmpString.flags |= ASN_LAST_FLAG;
    }

void ExtKeyUsageSyntax(struct ExtKeyUsageSyntax *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    simple_constructor(&mine->keyPurposeId, level, ASN_OBJ_ID);
    mine->keyPurposeId.flags |= ASN_LAST_FLAG;
    }

void AuthorityInfoAccessSyntax(struct AuthorityInfoAccessSyntax *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    AccessDescription(&mine->accessDescription, level);
    mine->accessDescription.self.flags |= ASN_LAST_FLAG;
    }

void AccessDescription(struct AccessDescription *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->accessMethod, level, ASN_OBJ_ID);
    GeneralName(&mine->accessLocation, level);
    mine->accessLocation.self.flags |= ASN_LAST_FLAG;
    }

void SBGPIpAddrBlock(struct SBGPIpAddrBlock *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    IPAddressFamily(&mine->iPAddressFamily, level);
    mine->iPAddressFamily.self.flags |= ASN_LAST_FLAG;
    }

void IPAddressFamily(struct IPAddressFamily *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->addressFamily, level, ASN_OCTETSTRING);
    mine->addressFamily.min = 2;
    mine->addressFamily.max = 3;
    IPAddressChoice(&mine->ipAddressChoice, level);
    mine->ipAddressChoice.self.flags |= ASN_LAST_FLAG;
    }

void IPAddressChoice(struct IPAddressChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->inherit, level, ASN_BOOLEAN);
    AddressesOrRangesInIPAddressChoice(&mine->addressesOrRanges, level);
    mine->addressesOrRanges.self.flags |= ASN_LAST_FLAG;
    }

void AddressesOrRangesInIPAddressChoice(struct AddressesOrRangesInIPAddressChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    IPAddressOrRange(&mine->iPAddressOrRange, level);
    mine->iPAddressOrRange.self.flags |= ASN_LAST_FLAG;
    }

void IPAddressOrRange(struct IPAddressOrRange *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->addressPrefix, level, ASN_BITSTRING);
    IPAddressRange(&mine->addressRange, level);
    mine->addressRange.self.flags |= ASN_LAST_FLAG;
    }

void IPAddressRange(struct IPAddressRange *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->min, level, ASN_BITSTRING);
    simple_constructor(&mine->max, level, ASN_BITSTRING);
    mine->max.flags |= ASN_LAST_FLAG;
    }

void SBGPASNum(struct SBGPASNum *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    ASIdentifierChoice(&mine->asnum, level);
    mine->asnum.self.tag = 0xA0;
    mine->asnum.self.flags |= ASN_OPTIONAL_FLAG;
    ASIdentifierChoice(&mine->rdi, level);
    mine->rdi.self.tag = 0xA1;
    mine->rdi.self.flags |= ASN_OPTIONAL_FLAG;
    mine->rdi.self.flags |= ASN_LAST_FLAG;
    }

void ASIdentifierChoice(struct ASIdentifierChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->inherit, level, ASN_BOOLEAN);
    AsNumbersOrRangesInASIdentifierChoice(&mine->asNumbersOrRanges, level);
    mine->asNumbersOrRanges.self.flags |= ASN_LAST_FLAG;
    }

void AsNumbersOrRangesInASIdentifierChoice(struct AsNumbersOrRangesInASIdentifierChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    ASNumberOrRange(&mine->aSNumberOrRange, level);
    mine->aSNumberOrRange.self.flags |= ASN_LAST_FLAG;
    }

void ASNumberOrRange(struct ASNumberOrRange *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->num, level, ASN_INTEGER);
    ASRange(&mine->range, level);
    mine->range.self.flags |= ASN_LAST_FLAG;
    }

void ASRange(struct ASRange *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->min, level, ASN_INTEGER);
    simple_constructor(&mine->max, level, ASN_INTEGER);
    mine->max.flags |= ASN_LAST_FLAG;
    }

void RouterIdentifier(struct RouterIdentifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    OwningASNumber(&mine->owningASNumber, level);
    mine->owningASNumber.self.flags |= ASN_LAST_FLAG;
    }

void OwningASNumber(struct OwningASNumber *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    tagged_constructor(&mine->asnum, level, ASN_INTEGER, 0x80);
    tagged_constructor(&mine->rdi, level, ASN_INTEGER, 0x81);
    mine->rdi.flags |= ASN_LAST_FLAG;
    }

