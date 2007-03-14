#ifndef _name_h
#define _name_h

#ifndef _casn_h
#include "casn.h"
#endif
#define id_attribute_types "2.5.4"
#define id_at "2.5.4"
#define id_objectClass "2.5.4.0"
#define id_aliasedObjectName "2.5.4.1"
#define id_knowledgeInformation "2.5.4.2"
#define id_commonName "2.5.4.3"
#define id_surname "2.5.4.4"
#define id_serialNumber "2.5.4.5"
#define id_countryName "2.5.4.6"
#define id_localityName "2.5.4.7"
#define id_stateOrProvinceName "2.5.4.8"
#define id_streetAddress "2.5.4.9"
#define id_organizationName "2.5.4.10"
#define id_organizationalUnitName "2.5.4.11"
#define id_title "2.5.4.12"
#define id_description "2.5.4.13"
#define id_searchGuide "2.5.4.14"
#define id_businessCategory "2.5.4.15"
#define id_postalAddress "2.5.4.16"
#define id_postalCode "2.5.4.17"
#define id_postOfficeBox "2.5.4.18"
#define id_physicalDeliveryOfficeName "2.5.4.19"
#define id_telephoneNumber "2.5.4.20"
#define id_telexNumber "2.5.4.21"
#define id_teletexTerminalIdentifier "2.5.4.22"
#define id_facsimileTelephoneNumberr "2.5.4.23"
#define id_x121Address "2.5.4.24"
#define id_internationalISDNNumber "2.5.4.25"
#define id_registeredAddress "2.5.4.26"
#define id_destinationIndicator "2.5.4.27"
#define id_preferredDeliveryMethod "2.5.4.28"
#define id_presentationAddress "2.5.4.29"
#define id_supportedApplicationContext "2.5.4.30"
#define id_member "2.5.4.31"
#define id_owner "2.5.4.32"
#define id_roleOccupant "2.5.4.33"
#define id_seeAlso "2.5.4.34"
#define id_userPassword "2.5.4.35"
#define id_userCertificate "2.5.4.36"
#define id_cACertificate "2.5.4.37"
#define id_authorityRevocationList "2.5.4.38"
#define id_certificateRevocationList "2.5.4.39"
#define id_crossCertificatePair "2.5.4.40"
#define id_name "2.5.4.41"
#define id_ipAddress "1.3.6.1.4.1.42.2.11.2.1"
#define id_at_uniqueIdentifier "2.5.4.45"
#define id_emailAddress "1.2.840.113549.1.9.1"
#define id_at_dc "0.9.2342.19200300.100.1.25"
#define ub_common_name 64
#define ub_surname 64
#define ub_serial_number 64
#define ub_locality_name 128
#define ub_state_name 128
#define ub_street_address 128
#define ub_organization_name 64
#define ub_organizational_unit_name 64
#define ub_title 64
#define ub_description 1024
#define ub_business_category 128
#define ub_postal_code 40
#define ub_post_office_box 40
#define ub_physical_office_name 128
#define ub_telephone_number 32
#define ub_x121_address 15
#define ub_isdn_address 16
#define ub_destination_indicator 128
#define ub_user_password 128
#define ub_name 64
#define ub_ipAddress 256

struct DirectoryString
    {
    struct casn self;
    struct casn printableString;
    struct casn teletexString;
    struct casn universalString;
    struct casn bMPString;
    };

void DirectoryString(struct DirectoryString *mine, ushort level);

void SelectedAttributeTypesInAttributeValueAssertion(struct casn *mine, ushort level);

struct SelectedAttributeTypesDefined
    {
    struct casn self;
    struct DirectoryString commonName;
    struct DirectoryString surname;
    struct casn serialNumber;
    struct casn countryName;
    struct DirectoryString localityName;
    struct DirectoryString stateOrProvinceName;
    struct DirectoryString streetAddress;
    struct DirectoryString organizationName;
    struct DirectoryString organizationalUnitName;
    struct DirectoryString title;
    struct DirectoryString description;
    struct DirectoryString businessCategory;
    struct DirectoryString postalCode;
    struct DirectoryString postOfficeBox;
    struct DirectoryString physicalDeliveryOfficeName;
    struct casn telephoneNumber;
    struct casn x121Address;
    struct casn internationalISDNNumber;
    struct casn destinationIndicator;
    struct casn userPassword;
    struct DirectoryString name;
    struct casn ipAddress;
    struct casn uniqueIdentifier;
    struct casn emailAddress;
    struct casn domainNameForm;
    struct casn unknown;
    };

void SelectedAttributeTypesDefined(struct SelectedAttributeTypesDefined *mine, ushort level);

struct AttributeValueAssertion
    {
    struct casn self;
    struct casn objid;
    struct SelectedAttributeTypesDefined value;
    };

void AttributeValueAssertion(struct AttributeValueAssertion *mine, ushort level);

struct RelativeDistinguishedName
    {
    struct casn self;
    struct AttributeValueAssertion attributeValueAssertion;
    };

void RelativeDistinguishedName(struct RelativeDistinguishedName *mine, ushort level);

struct RDNSequence
    {
    struct casn self;
    struct RelativeDistinguishedName relativeDistinguishedName;
    };

void RDNSequence(struct RDNSequence *mine, ushort level);

#define DistinguishedName RDNSequence

struct Name
    {
    struct casn self;
    struct RDNSequence rDNSequence;
    };

void Name(struct Name *mine, ushort level);

struct AttributeValueChoice
    {
    struct casn self;
    struct casn objid;
    struct DirectoryString value;
    };

void AttributeValueChoice(struct AttributeValueChoice *mine, ushort level);

#define AliasedObjectName RDNSequence

#define GenName DirectoryString

#endif /* name_h */
