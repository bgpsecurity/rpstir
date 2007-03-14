#ifndef _name_h
#include "name.h"
#endif

void Name(struct Name *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    RDNSequence(&mine->rDNSequence, level);
    mine->rDNSequence.self.flags |= ASN_LAST_FLAG;
    }

void RDNSequence(struct RDNSequence *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    RelativeDistinguishedName(&mine->relativeDistinguishedName, level);
    mine->relativeDistinguishedName.self.flags |= ASN_LAST_FLAG;
    }

void RelativeDistinguishedName(struct RelativeDistinguishedName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    AttributeValueAssertion(&mine->attributeValueAssertion, level);
    mine->attributeValueAssertion.self.flags |= ASN_LAST_FLAG;
    }

void AttributeValueAssertion(struct AttributeValueAssertion *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    SelectedAttributeTypesInAttributeValueAssertion(&mine->objid, level);
    SelectedAttributeTypesDefined(&mine->value, level);
    mine->value.self.flags |= ASN_LAST_FLAG;
    }

void AttributeValueChoice(struct AttributeValueChoice *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->objid, level, ASN_OBJ_ID);
    DirectoryString(&mine->value, level);
    mine->value.self.flags |= ASN_LAST_FLAG;
    }

void SelectedAttributeTypesInAttributeValueAssertion(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(27, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"1";
    tcasnp->lth = 26;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.3");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.5");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.6");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.7");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.8");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.9");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.10");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.11");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.12");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.13");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.15");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.17");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.18");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.19");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.20");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.24");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.25");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.27");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.35");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.41");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.6.1.4.1.42.2.11.2.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.5.4.45");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.9.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "0.9.2342.19200300.100.1.25");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void SelectedAttributeTypesDefined(struct SelectedAttributeTypesDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    DirectoryString(&mine->commonName, level);
    mine->commonName.self.min = 1;
    mine->commonName.self.max = 64;
    DirectoryString(&mine->surname, level);
    mine->surname.self.min = 1;
    mine->surname.self.max = 64;
    simple_constructor(&mine->serialNumber, level, ASN_PRINTABLE_STRING);
    mine->serialNumber.min = 1;
    mine->serialNumber.max = 64;
    simple_constructor(&mine->countryName, level, ASN_PRINTABLE_STRING);
    mine->countryName.min = 2;
    mine->countryName.max = 2;
    DirectoryString(&mine->localityName, level);
    mine->localityName.self.min = 1;
    mine->localityName.self.max = 128;
    DirectoryString(&mine->stateOrProvinceName, level);
    mine->stateOrProvinceName.self.min = 1;
    mine->stateOrProvinceName.self.max = 128;
    DirectoryString(&mine->streetAddress, level);
    mine->streetAddress.self.min = 1;
    mine->streetAddress.self.max = 128;
    DirectoryString(&mine->organizationName, level);
    mine->organizationName.self.min = 1;
    mine->organizationName.self.max = 64;
    DirectoryString(&mine->organizationalUnitName, level);
    mine->organizationalUnitName.self.min = 1;
    mine->organizationalUnitName.self.max = 64;
    DirectoryString(&mine->title, level);
    mine->title.self.min = 1;
    mine->title.self.max = 64;
    DirectoryString(&mine->description, level);
    mine->description.self.min = 1;
    mine->description.self.max = 1024;
    DirectoryString(&mine->businessCategory, level);
    mine->businessCategory.self.min = 1;
    mine->businessCategory.self.max = 128;
    DirectoryString(&mine->postalCode, level);
    mine->postalCode.self.min = 1;
    mine->postalCode.self.max = 40;
    DirectoryString(&mine->postOfficeBox, level);
    mine->postOfficeBox.self.min = 1;
    mine->postOfficeBox.self.max = 40;
    DirectoryString(&mine->physicalDeliveryOfficeName, level);
    mine->physicalDeliveryOfficeName.self.min = 1;
    mine->physicalDeliveryOfficeName.self.max = 128;
    simple_constructor(&mine->telephoneNumber, level, ASN_PRINTABLE_STRING);
    mine->telephoneNumber.min = 1;
    mine->telephoneNumber.max = 32;
    simple_constructor(&mine->x121Address, level, ASN_NUMERIC_STRING);
    mine->x121Address.min = 1;
    mine->x121Address.max = 15;
    simple_constructor(&mine->internationalISDNNumber, level, ASN_NUMERIC_STRING);
    mine->internationalISDNNumber.min = 1;
    mine->internationalISDNNumber.max = 16;
    simple_constructor(&mine->destinationIndicator, level, ASN_PRINTABLE_STRING);
    mine->destinationIndicator.min = 1;
    mine->destinationIndicator.max = 128;
    simple_constructor(&mine->userPassword, level, ASN_OCTETSTRING);
    mine->userPassword.min = 1;
    mine->userPassword.max = 128;
    DirectoryString(&mine->name, level);
    mine->name.self.min = 1;
    mine->name.self.max = 64;
    simple_constructor(&mine->ipAddress, level, ASN_PRINTABLE_STRING);
    mine->ipAddress.min = 1;
    mine->ipAddress.max = 256;
    simple_constructor(&mine->uniqueIdentifier, level, ASN_BITSTRING);
    simple_constructor(&mine->emailAddress, level, ASN_IA5_STRING);
    simple_constructor(&mine->domainNameForm, level, ASN_IA5_STRING);
    simple_constructor(&mine->unknown, level, ASN_ANY);
    mine->unknown.flags |= ASN_LAST_FLAG;
    }

void DirectoryString(struct DirectoryString *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->printableString, level, ASN_PRINTABLE_STRING);
    mine->printableString.min = 1;
    mine->printableString.max = 64;
    simple_constructor(&mine->teletexString, level, ASN_T61_STRING);
    mine->teletexString.min = 1;
    mine->teletexString.max = 64;
    simple_constructor(&mine->universalString, level, ASN_UNIVERSAL_STRING);
    mine->universalString.min = 1;
    mine->universalString.max = 64;
    simple_constructor(&mine->bMPString, level, ASN_BMP_STRING);
    mine->bMPString.flags |= ASN_LAST_FLAG;
    }

