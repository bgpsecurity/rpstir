#ifndef _orname_h
#include "orname.h"
#endif

void ORName(struct ORName *mine, ushort level)
    {
    tagged_constructor(&mine->self, level++, ASN_SEQUENCE, 0x60);
    StandardAttributes(&mine->standard_attributes, level);
    DomainDefinedAttributes(&mine->domain_defined_attributes, level);
    mine->domain_defined_attributes.self.flags |= ASN_OPTIONAL_FLAG;
    ExtensionAttributes(&mine->extension_attributes, level);
    mine->extension_attributes.self.flags |= ASN_OPTIONAL_FLAG;
    Name(&mine->directory_name, level);
    mine->directory_name.self.tag = 0xA0;
    mine->directory_name.self.flags |= ASN_OPTIONAL_FLAG;
    mine->directory_name.self.flags |= ASN_LAST_FLAG;
    }

void ORAddress(struct ORAddress *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    StandardAttributes(&mine->standard_attributes, level);
    DomainDefinedAttributes(&mine->domain_defined_attributes, level);
    mine->domain_defined_attributes.self.flags |= ASN_OPTIONAL_FLAG;
    ExtensionAttributes(&mine->extension_attributes, level);
    mine->extension_attributes.self.flags |= ASN_OPTIONAL_FLAG;
    mine->extension_attributes.self.flags |= ASN_LAST_FLAG;
    }

void StandardAttributes(struct StandardAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    CountryName(&mine->country_name, level);
    mine->country_name.self.flags |= ASN_OPTIONAL_FLAG;
    AdministrationDomainName(&mine->administration_domain_name, level);
    mine->administration_domain_name.self.flags |= ASN_OPTIONAL_FLAG;
    X121Address(&mine->network_address, level);
    mine->network_address.self.tag = 0x80;
    mine->network_address.self.min = 1;
    mine->network_address.self.max = 15;
    mine->network_address.self.flags |= ASN_OPTIONAL_FLAG;
    TerminalIdentifier(&mine->terminal_identifier, level);
    mine->terminal_identifier.self.tag = 0x81;
    mine->terminal_identifier.self.min = 1;
    mine->terminal_identifier.self.max = 24;
    mine->terminal_identifier.self.flags |= ASN_OPTIONAL_FLAG;
    PrivateDomainName(&mine->private_domain_name, level);
    mine->private_domain_name.self.tag = 0xA2;
    mine->private_domain_name.self.flags |= ASN_OPTIONAL_FLAG;
    OrganizationName(&mine->organization_name, level);
    mine->organization_name.self.tag = 0x83;
    mine->organization_name.self.min = 1;
    mine->organization_name.self.max = 64;
    mine->organization_name.self.flags |= ASN_OPTIONAL_FLAG;
    NumericUserIdentifier(&mine->numeric_user_identifier, level);
    mine->numeric_user_identifier.self.tag = 0x84;
    mine->numeric_user_identifier.self.min = 1;
    mine->numeric_user_identifier.self.max = 32;
    mine->numeric_user_identifier.self.flags |= ASN_OPTIONAL_FLAG;
    PersonalName(&mine->personal_name, level);
    mine->personal_name.self.tag = 0xA5;
    mine->personal_name.self.flags |= ASN_OPTIONAL_FLAG;
    OrganizationalUnitNames(&mine->organizational_unit_names, level);
    mine->organizational_unit_names.self.tag = 0xA6;
    mine->organizational_unit_names.self.flags |= ASN_OPTIONAL_FLAG;
    mine->organizational_unit_names.self.flags |= ASN_LAST_FLAG;
    }

void CountryName(struct CountryName *mine, ushort level)
    {
    tagged_constructor(&mine->self, level++, ASN_CHOICE, 0x61);
    simple_constructor(&mine->x121_dcc_code, level, ASN_NUMERIC_STRING);
    mine->x121_dcc_code.min = 3;
    mine->x121_dcc_code.max = 3;
    simple_constructor(&mine->iso_3166_alpha2_code, level, ASN_PRINTABLE_STRING);
    mine->iso_3166_alpha2_code.min = 2;
    mine->iso_3166_alpha2_code.max = 2;
    mine->iso_3166_alpha2_code.flags |= ASN_LAST_FLAG;
    }

void AdministrationDomainName(struct AdministrationDomainName *mine, ushort level)
    {
    tagged_constructor(&mine->self, level++, ASN_CHOICE, 0x62);
    simple_constructor(&mine->numeric, level, ASN_NUMERIC_STRING);
    mine->numeric.min = 0;
    mine->numeric.max = 16;
    simple_constructor(&mine->printable, level, ASN_PRINTABLE_STRING);
    mine->printable.min = 0;
    mine->printable.max = 16;
    mine->printable.flags |= ASN_LAST_FLAG;
    }

void X121Address(struct X121Address *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_NUMERIC_STRING);
    mine->self.min = 1;
    mine->self.max = 15;
    }

void TerminalIdentifier(struct TerminalIdentifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_PRINTABLE_STRING);
    mine->self.min = 1;
    mine->self.max = 24;
    }

void PrivateDomainName(struct PrivateDomainName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    simple_constructor(&mine->numeric, level, ASN_NUMERIC_STRING);
    mine->numeric.min = 1;
    mine->numeric.max = 16;
    simple_constructor(&mine->printable, level, ASN_PRINTABLE_STRING);
    mine->printable.min = 1;
    mine->printable.max = 16;
    mine->printable.flags |= ASN_LAST_FLAG;
    }

void OrganizationName(struct OrganizationName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_PRINTABLE_STRING);
    mine->self.min = 1;
    mine->self.max = 64;
    }

void NumericUserIdentifier(struct NumericUserIdentifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_NUMERIC_STRING);
    mine->self.min = 1;
    mine->self.max = 32;
    }

void PersonalName(struct PersonalName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    tagged_constructor(&mine->surname, level, ASN_PRINTABLE_STRING, 0x80);
    mine->surname.min = 1;
    mine->surname.max = 40;
    tagged_constructor(&mine->given_name, level, ASN_PRINTABLE_STRING, 0x81);
    mine->given_name.flags |= ASN_OPTIONAL_FLAG;
    mine->given_name.min = 1;
    mine->given_name.max = 16;
    tagged_constructor(&mine->initials, level, ASN_PRINTABLE_STRING, 0x82);
    mine->initials.flags |= ASN_OPTIONAL_FLAG;
    mine->initials.min = 1;
    mine->initials.max = 5;
    tagged_constructor(&mine->generational_qualifier, level, ASN_PRINTABLE_STRING, 0x83);
    mine->generational_qualifier.flags |= ASN_OPTIONAL_FLAG;
    mine->generational_qualifier.min = 1;
    mine->generational_qualifier.max = 3;
    mine->generational_qualifier.flags |= ASN_LAST_FLAG;
    }

void OrganizationalUnitNames(struct OrganizationalUnitNames *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 4;
    simple_constructor(&mine->organizationalUnitName, level, ASN_PRINTABLE_STRING);
    mine->organizationalUnitName.min = 1;
    mine->organizationalUnitName.max = 32;
    mine->organizationalUnitName.flags |= ASN_LAST_FLAG;
    }

void OrganizationalUnitName(struct OrganizationalUnitName *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_PRINTABLE_STRING);
    mine->self.min = 1;
    mine->self.max = 32;
    }

void DomainDefinedAttributes(struct DomainDefinedAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 4;
    DomainDefinedAttribute(&mine->domainDefinedAttribute, level);
    mine->domainDefinedAttribute.self.flags |= ASN_LAST_FLAG;
    }

void DomainDefinedAttribute(struct DomainDefinedAttribute *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->type, level, ASN_PRINTABLE_STRING);
    mine->type.min = 1;
    mine->type.max = 8;
    simple_constructor(&mine->value, level, ASN_PRINTABLE_STRING);
    mine->value.min = 1;
    mine->value.max = 128;
    mine->value.flags |= ASN_LAST_FLAG;
    }

void ExtensionAttributes(struct ExtensionAttributes *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SET);
    mine->self.flags |= ASN_OF_FLAG;
    mine->self.min = 1;
    mine->self.max = 256;
    ExtensionAttribute(&mine->extensionAttribute, level);
    mine->extensionAttribute.self.flags |= ASN_LAST_FLAG;
    }

void ExtensionAttribute(struct ExtensionAttribute *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    tagged_constructor(&mine->extension_attribute_type, level, ASN_INTEGER, 0x80);
    mine->extension_attribute_type.flags |= ASN_LAST_FLAG;
    }

