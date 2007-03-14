#ifndef _orname_h
#define _orname_h

#ifndef _casn_h
#include "casn.h"
#endif
#ifndef _name_h
#include "name.h"
#endif
#define ub_country_name_numeric_length 3
#define ub_country_name_alpha_length 2
#define ub_domain_name_length 16
#define ub_organization_name_length 64
#define ub_numeric_user_id_length 32
#define ub_surname_length 40
#define ub_given_name_length 16
#define ub_initials_length 5
#define ub_generational_qualifier_length 3
#define ub_organizational_units 4
#define ub_organizational_unit_name_length 32
#define ub_domain_defined_attributes 4
#define ub_domain_attribute_type_length 8
#define ub_domain_attribute_value_length 128
#define ub_extension_attributes 256
#define ub_x121_address_length 15
#define ub_terminal_id_length 24

struct X121Address
    {
    struct casn self;
    };

void X121Address(struct X121Address *mine, ushort level);

struct OrganizationalUnitName
    {
    struct casn self;
    };

void OrganizationalUnitName(struct OrganizationalUnitName *mine, ushort level);

struct CountryName
    {
    struct casn self;
    struct casn x121_dcc_code;
    struct casn iso_3166_alpha2_code;
    };

void CountryName(struct CountryName *mine, ushort level);

struct AdministrationDomainName
    {
    struct casn self;
    struct casn numeric;
    struct casn printable;
    };

void AdministrationDomainName(struct AdministrationDomainName *mine, ushort level);

struct TerminalIdentifier
    {
    struct casn self;
    };

void TerminalIdentifier(struct TerminalIdentifier *mine, ushort level);

struct PrivateDomainName
    {
    struct casn self;
    struct casn numeric;
    struct casn printable;
    };

void PrivateDomainName(struct PrivateDomainName *mine, ushort level);

struct OrganizationName
    {
    struct casn self;
    };

void OrganizationName(struct OrganizationName *mine, ushort level);

struct NumericUserIdentifier
    {
    struct casn self;
    };

void NumericUserIdentifier(struct NumericUserIdentifier *mine, ushort level);

struct PersonalName
    {
    struct casn self;
    struct casn surname;
    struct casn given_name;
    struct casn initials;
    struct casn generational_qualifier;
    };

void PersonalName(struct PersonalName *mine, ushort level);

struct OrganizationalUnitNames
    {
    struct casn self;
    struct casn organizationalUnitName;
    };

void OrganizationalUnitNames(struct OrganizationalUnitNames *mine, ushort level);

struct DomainDefinedAttribute
    {
    struct casn self;
    struct casn type;
    struct casn value;
    };

void DomainDefinedAttribute(struct DomainDefinedAttribute *mine, ushort level);

struct ExtensionAttribute
    {
    struct casn self;
    struct casn extension_attribute_type;
    };

void ExtensionAttribute(struct ExtensionAttribute *mine, ushort level);

#define NetworkAddress casn

struct StandardAttributes
    {
    struct casn self;
    struct CountryName country_name;
    struct AdministrationDomainName administration_domain_name;
    struct X121Address network_address;
    struct TerminalIdentifier terminal_identifier;
    struct PrivateDomainName private_domain_name;
    struct OrganizationName organization_name;
    struct NumericUserIdentifier numeric_user_identifier;
    struct PersonalName personal_name;
    struct OrganizationalUnitNames organizational_unit_names;
    };

void StandardAttributes(struct StandardAttributes *mine, ushort level);

struct DomainDefinedAttributes
    {
    struct casn self;
    struct DomainDefinedAttribute domainDefinedAttribute;
    };

void DomainDefinedAttributes(struct DomainDefinedAttributes *mine, ushort level);

struct ExtensionAttributes
    {
    struct casn self;
    struct ExtensionAttribute extensionAttribute;
    };

void ExtensionAttributes(struct ExtensionAttributes *mine, ushort level);

struct ORAddress
    {
    struct casn self;
    struct StandardAttributes standard_attributes;
    struct DomainDefinedAttributes domain_defined_attributes;
    struct ExtensionAttributes extension_attributes;
    };

void ORAddress(struct ORAddress *mine, ushort level);

struct ORName
    {
    struct casn self;
    struct StandardAttributes standard_attributes;
    struct DomainDefinedAttributes domain_defined_attributes;
    struct ExtensionAttributes extension_attributes;
    struct Name directory_name;
    };

void ORName(struct ORName *mine, ushort level);

#define ORAddressAndOrDirectoryName ORName

#endif /* orname_h */
