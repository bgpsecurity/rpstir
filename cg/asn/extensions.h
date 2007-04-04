#ifndef _extensions_h
#define _extensions_h

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
#define id_ce "2.5.29"
#define id_subjectDirectoryAttributes "2.5.29.9"
#define id_subjectKeyIdentifier "2.5.29.14"
#define id_keyUsage "2.5.29.15"
#define id_privateKeyUsagePeriod "2.5.29.16"
#define id_subjectAltName "2.5.29.17"
#define id_issuerAltName "2.5.29.18"
#define id_basicConstraints "2.5.29.19"
#define id_cRLNumber "2.5.29.20"
#define id_reasonCode "2.5.29.21"
#define id_instructionCode "2.5.29.23"
#define id_invalidityDate "2.5.29.24"
#define id_deltaCRLIndicator "2.5.29.27"
#define id_issuingDistributionPoint "2.5.29.28"
#define id_certificateIssuer "2.5.29.29"
#define id_nameConstraints "2.5.29.30"
#define id_cRLDistributionPoints "2.5.29.31"
#define id_certificatePolicies "2.5.29.32"
#define id_policyMappings "2.5.29.33"
#define id_authKeyId "2.5.29.35"
#define id_policyConstraints "2.5.29.36"
#define id_extKeyUsage "2.5.29.37"
#define id_set_certExt "2.23.42.7"
#define id_set_hashedRootKey "2.23.42.7.0"
#define id_set_certificateType "2.23.42.7.1"
#define id_set_merchantData "2.23.42.7.2"
#define id_set_cardCertRequired "2.23.42.7.3"
#define id_set_tunneling "2.23.42.7.4"
#define id_set_setExtensions "2.23.42.7.5"
#define id_set_setQualifier "2.23.42.7.6"
#define id_pkix "1.3.6.1.5.5.7"
#define id_pkix_pe "1.3.6.1.5.5.7.1"
#define id_pkix_qt "1.3.6.1.5.5.7.2"
#define id_pkix_kp "1.3.6.1.5.5.7.3"
#define id_pkix_it "1.3.6.1.5.5.7.4"
#define id_pkix_ad "1.3.6.1.5.5.7.48"
#define id_pkix_authorityInfoAccess "1.3.6.1.5.5.7.1.1"
#define id_pkix_cps "1.3.6.1.5.5.7.2.1"
#define id_pkix_unotice "1.3.6.1.5.5.7.2.2"
#define id_pkix_serverAuth "1.3.6.1.5.5.7.3.1"
#define id_pkix_clientAuth "1.3.6.1.5.5.7.3.2"
#define id_pkix_codeSigning "1.3.6.1.5.5.7.3.3"
#define id_pkix_emailProtection "1.3.6.1.5.5.7.3.4"
#define id_pkix_ipsecEndSystem "1.3.6.1.5.5.7.3.5"
#define id_pkix_ipsecTunnel "1.3.6.1.5.5.7.3.6"
#define id_pkix_ipsecUser "1.3.6.1.5.5.7.3.7"
#define id_pkix_timeStamping "1.3.6.1.5.5.7.3.8"
#define id_pkix_caProtEncCert "1.3.6.1.5.5.7.4.1"
#define id_pkix_signKeyPairTypes "1.3.6.1.5.5.7.4.2"
#define id_pkix_encKeyPairTypes "1.3.6.1.5.5.7.4.3"
#define id_pkix_preferredSymmAlg "1.3.6.1.5.5.7.4.4"
#define id_pkix_caKeyUpdateInfo "1.3.6.1.5.5.7.4.5"
#define id_pkix_currentCRL "1.3.6.1.5.5.7.4.6"
#define id_pkix_ocsp "1.3.6.1.5.5.7.48.1"
#define id_pkix_caIssuers "1.3.6.1.5.5.7.48.2"
#define id_pe_sbgp_ipAddrBlock "1.3.6.1.5.5.7.1.7"
#define id_pe_sbgp_autonomousSysNum "1.3.6.1.5.5.7.1.8"
#define id_pe_sbgp_routerIdentifier "1.3.6.1.5.5.7.1.9"
#define OPTIONAL_EXTENSION 0
#define MANDATORY_EXTENSION 1
#define DEPRECATED_EXTENSION 2
#define NON_CRITICAL_EXTENSION 0
#define CRITICAL_EXTENSION 1
#define ub_countryName 50
#define ub_cityName 50
#define ub_merName 25
#define ub_postalCode 14
#define ub_stateProvince 25
#define ub_terseStatement 2048
#define ub_RFC1766_language 35
#define ub_MerchantID 30
#define ub_url 512

struct URL
    {
    struct casn self;
    };

void URL(struct URL *mine, ushort level);

struct TerseStatementInSETQualifier
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void TerseStatementInSETQualifier(struct TerseStatementInSETQualifier *mine, ushort level);

#define CertPolicyId casn

struct CertificateType
    {
    struct casn self;
    struct casn card;
    struct casn mer;
    struct casn pgwy;
    struct casn cca;
    struct casn mca;
    struct casn pca;
    struct casn gca;
    struct casn bca;
    struct casn rca;
    struct casn acq;
    };

void CertificateType(struct CertificateType *mine, ushort level);

struct SETQualifier
    {
    struct casn self;
    struct TerseStatementInSETQualifier terseStatement;
    struct URL policyURL;
    struct URL policyEmail;
    };

void SETQualifier(struct SETQualifier *mine, ushort level);

void Other_nameTableInOther_name(struct casn *mine, ushort level);

struct Other_nameTableDefined
    {
    struct casn self;
    struct casn any;
    };

void Other_nameTableDefined(struct Other_nameTableDefined *mine, ushort level);

struct AdditionalPolicy
    {
    struct casn self;
    struct casn policyOID;
    struct SETQualifier policyQualifier;
    struct CertificateType policyAddedBy;
    };

void AdditionalPolicy(struct AdditionalPolicy *mine, ushort level);

struct NoticeNumbersInNoticeReference
    {
    struct casn self;
    struct casn array;
    };

void NoticeNumbersInNoticeReference(struct NoticeNumbersInNoticeReference *mine, ushort level);

struct NoticeReference
    {
    struct casn self;
    struct casn organization;
    struct NoticeNumbersInNoticeReference noticeNumbers;
    };

void NoticeReference(struct NoticeReference *mine, ushort level);

struct DisplayText
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void DisplayText(struct DisplayText *mine, ushort level);

struct AdditionalPolicies
    {
    struct casn self;
    struct AdditionalPolicy additionalPolicy;
    };

void AdditionalPolicies(struct AdditionalPolicies *mine, ushort level);

struct Other_name
    {
    struct casn self;
    struct casn type_id;
    struct Other_nameTableDefined value;
    };

void Other_name(struct Other_name *mine, ushort level);

#define CPSuri casn

struct UserNotice
    {
    struct casn self;
    struct NoticeReference noticeRef;
    struct DisplayText explicitText;
    };

void UserNotice(struct UserNotice *mine, ushort level);

struct SetPolicyQualifier
    {
    struct casn self;
    struct SETQualifier rootQualifier;
    struct AdditionalPolicies additionalPolicies;
    };

void SetPolicyQualifier(struct SetPolicyQualifier *mine, ushort level);

struct EDIPartyName
    {
    struct casn self;
    struct DirectoryString nameAssigner;
    struct DirectoryString partyName;
    };

void EDIPartyName(struct EDIPartyName *mine, ushort level);

#define IPAddressA casn

void PolicyQualifierInfoSetInPolicyQualifierInfo(struct casn *mine, ushort level);

struct PolicyQualifierInfoSetDefined
    {
    struct casn self;
    struct casn cPSuri;
    struct UserNotice userNotice;
    struct SetPolicyQualifier setQualifier;
    struct casn any;
    };

void PolicyQualifierInfoSetDefined(struct PolicyQualifierInfoSetDefined *mine, ushort level);

struct IPAddressRangeA
    {
    struct casn self;
    struct casn min;
    struct casn max;
    };

void IPAddressRangeA(struct IPAddressRangeA *mine, ushort level);

struct GeneralName
    {
    struct casn self;
    struct Other_name otherName;
    struct casn rfc822Name;
    struct casn dNSName;
    struct ORAddress x400Address;
    struct Name directoryName;
    struct EDIPartyName ediPartyName;
    struct casn url;
    struct casn iPAddress;
    struct casn registeredID;
    };

void GeneralName(struct GeneralName *mine, ushort level);

#define ASNumberA casn

void AttributeTableInAttribute(struct casn *mine, ushort level);

struct AttributeTableDefined
    {
    struct casn self;
    struct casn any;
    };

void AttributeTableDefined(struct AttributeTableDefined *mine, ushort level);

struct IPAddressOrRangeA
    {
    struct casn self;
    struct casn addressPrefix;
    struct IPAddressRangeA addressRange;
    };

void IPAddressOrRangeA(struct IPAddressOrRangeA *mine, ushort level);

struct GeneralNames
    {
    struct casn self;
    struct GeneralName generalName;
    };

void GeneralNames(struct GeneralNames *mine, ushort level);

struct ASRangeA
    {
    struct casn self;
    struct casn min;
    struct casn max;
    };

void ASRangeA(struct ASRangeA *mine, ushort level);

struct PolicyQualifierInfo
    {
    struct casn self;
    struct casn policyQualifierId;
    struct PolicyQualifierInfoSetDefined qualifier;
    };

void PolicyQualifierInfo(struct PolicyQualifierInfo *mine, ushort level);

#define BaseDistance casn

struct Language
    {
    struct casn self;
    };

void Language(struct Language *mine, ushort level);

struct ASNumberOrRangeA
    {
    struct casn self;
    struct casn num;
    struct ASRangeA range;
    };

void ASNumberOrRangeA(struct ASNumberOrRangeA *mine, ushort level);

struct NameInMerNames
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void NameInMerNames(struct NameInMerNames *mine, ushort level);

struct CityInMerNames
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void CityInMerNames(struct CityInMerNames *mine, ushort level);

struct StateProvinceInMerNames
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void StateProvinceInMerNames(struct StateProvinceInMerNames *mine, ushort level);

struct PostalCodeInMerNames
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void PostalCodeInMerNames(struct PostalCodeInMerNames *mine, ushort level);

struct CountryNameInMerNames
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void CountryNameInMerNames(struct CountryNameInMerNames *mine, ushort level);

struct AddressesOrRangesInIPAddressChoiceA
    {
    struct casn self;
    struct IPAddressOrRangeA iPAddressOrRangeA;
    };

void AddressesOrRangesInIPAddressChoiceA(struct AddressesOrRangesInIPAddressChoiceA *mine, ushort level);

struct DistributionPointName
    {
    struct casn self;
    struct GeneralNames fullName;
    struct RelativeDistinguishedName nameRelativeToCRLIssuer;
    };

void DistributionPointName(struct DistributionPointName *mine, ushort level);

struct ReasonFlags
    {
    struct casn self;
    struct casn unused;
    struct casn keyCompromise;
    struct casn caCompromise;
    struct casn affiliationChanged;
    struct casn superseded;
    struct casn cessationOfOperation;
    struct casn certificateHold;
    };

void ReasonFlags(struct ReasonFlags *mine, ushort level);

struct GeneralSubtree
    {
    struct casn self;
    struct GeneralName base;
    struct casn minimum;
    struct casn maximum;
    };

void GeneralSubtree(struct GeneralSubtree *mine, ushort level);

#define CRLNumber casn

struct MerNames
    {
    struct casn self;
    struct Language language;
    struct NameInMerNames name;
    struct CityInMerNames city;
    struct StateProvinceInMerNames stateProvince;
    struct PostalCodeInMerNames postalCode;
    struct CountryNameInMerNames countryName;
    };

void MerNames(struct MerNames *mine, ushort level);

struct IPAddressChoiceA
    {
    struct casn self;
    struct casn inherit;
    struct AddressesOrRangesInIPAddressChoiceA addressesOrRanges;
    };

void IPAddressChoiceA(struct IPAddressChoiceA *mine, ushort level);

struct PolicyQualifiersInPolicyInformation
    {
    struct casn self;
    struct PolicyQualifierInfo policyQualifierInfo;
    };

void PolicyQualifiersInPolicyInformation(struct PolicyQualifiersInPolicyInformation *mine, ushort level);

struct ValuesInAttribute
    {
    struct casn self;
    struct AttributeTableDefined array;
    };

void ValuesInAttribute(struct ValuesInAttribute *mine, ushort level);

struct AsNumbersOrRangesInASIdentifierChoiceA
    {
    struct casn self;
    struct ASNumberOrRangeA aSNumberOrRangeA;
    };

void AsNumbersOrRangesInASIdentifierChoiceA(struct AsNumbersOrRangesInASIdentifierChoiceA *mine, ushort level);

#define KeyIdentifier casn

struct Attribute
    {
    struct casn self;
    struct casn type;
    struct ValuesInAttribute values;
    };

void Attribute(struct Attribute *mine, ushort level);

struct PolicyInformation
    {
    struct casn self;
    struct casn policyIdentifier;
    struct PolicyQualifiersInPolicyInformation policyQualifiers;
    };

void PolicyInformation(struct PolicyInformation *mine, ushort level);

struct DistributionPoint
    {
    struct casn self;
    struct DistributionPointName distributionPoint;
    struct ReasonFlags reasons;
    struct GeneralNames cRLIssuer;
    };

void DistributionPoint(struct DistributionPoint *mine, ushort level);

struct SequenceInPolicyMappings
    {
    struct casn self;
    struct casn issuerDomainPolicy;
    struct casn subjectDomainPolicy;
    };

void SequenceInPolicyMappings(struct SequenceInPolicyMappings *mine, ushort level);

struct GeneralSubtrees
    {
    struct casn self;
    struct GeneralSubtree generalSubtree;
    };

void GeneralSubtrees(struct GeneralSubtrees *mine, ushort level);

#define SkipCerts casn

struct BIN
    {
    struct casn self;
    };

void BIN(struct BIN *mine, ushort level);

struct CountryCode
    {
    struct casn self;
    };

void CountryCode(struct CountryCode *mine, ushort level);

struct MerNameSeq
    {
    struct casn self;
    struct MerNames merNames;
    };

void MerNameSeq(struct MerNameSeq *mine, ushort level);

struct TunnelAlg
    {
    struct casn self;
    struct casn iD;
    };

void TunnelAlg(struct TunnelAlg *mine, ushort level);

#define KeyPurposeId casn

struct AccessDescription
    {
    struct casn self;
    struct casn accessMethod;
    struct GeneralName accessLocation;
    };

void AccessDescription(struct AccessDescription *mine, ushort level);

struct IPAddressFamilyA
    {
    struct casn self;
    struct casn addressFamily;
    struct IPAddressChoiceA ipAddressChoice;
    };

void IPAddressFamilyA(struct IPAddressFamilyA *mine, ushort level);

struct ASIdentifierChoiceA
    {
    struct casn self;
    struct casn inherit;
    struct AsNumbersOrRangesInASIdentifierChoiceA asNumbersOrRanges;
    };

void ASIdentifierChoiceA(struct ASIdentifierChoiceA *mine, ushort level);

struct OwningASNumber
    {
    struct casn self;
    struct casn asnum;
    struct casn rdi;
    };

void OwningASNumber(struct OwningASNumber *mine, ushort level);

struct MerchantID
    {
    struct casn self;
    struct casn visibleString;
    struct casn bmpString;
    };

void MerchantID(struct MerchantID *mine, ushort level);

#define BaseCRLNumber casn

struct AuthorityKeyId
    {
    struct casn self;
    struct casn keyIdentifier;
    struct GeneralNames certIssuer;
    struct casn certSerialNumber;
    };

void AuthorityKeyId(struct AuthorityKeyId *mine, ushort level);

int AuthorityKeyIdConstraint(struct AuthorityKeyId *);

#define SubjectKeyIdentifier casn

struct KeyUsage
    {
    struct casn self;
    struct casn digitalSignature;
    struct casn nonRepudiation;
    struct casn keyEncipherment;
    struct casn dataEncipherment;
    struct casn keyAgreement;
    struct casn keyCertSign;
    struct casn cRLSign;
    struct casn encipherOnly;
    struct casn decipherOnly;
    };

void KeyUsage(struct KeyUsage *mine, ushort level);

struct PrivateKeyUsagePeriod
    {
    struct casn self;
    struct casn notBefore;
    struct casn notAfter;
    };

void PrivateKeyUsagePeriod(struct PrivateKeyUsagePeriod *mine, ushort level);

int PrivateKeyUsagePeriodConstraint(struct PrivateKeyUsagePeriod *);

struct CertificatePolicies
    {
    struct casn self;
    struct PolicyInformation policyInformation;
    };

void CertificatePolicies(struct CertificatePolicies *mine, ushort level);

struct PolicyMappings
    {
    struct casn self;
    struct SequenceInPolicyMappings sequenceInPolicyMappings;
    };

void PolicyMappings(struct PolicyMappings *mine, ushort level);

#define AltNames GeneralNames

struct SubjectDirectoryAttributes
    {
    struct casn self;
    struct Attribute attribute;
    };

void SubjectDirectoryAttributes(struct SubjectDirectoryAttributes *mine, ushort level);

struct BasicConstraints
    {
    struct casn self;
    struct casn cA;
    struct casn pathLenConstraint;
    };

void BasicConstraints(struct BasicConstraints *mine, ushort level);

struct NameConstraints
    {
    struct casn self;
    struct GeneralSubtrees permittedSubtrees;
    struct GeneralSubtrees excludedSubtrees;
    };

void NameConstraints(struct NameConstraints *mine, ushort level);

struct PolicyConstraints
    {
    struct casn self;
    struct casn requireExplicitPolicy;
    struct casn inhibitPolicyMapping;
    };

void PolicyConstraints(struct PolicyConstraints *mine, ushort level);

struct CRLDistributionPoints
    {
    struct casn self;
    struct DistributionPoint distributionPoint;
    };

void CRLDistributionPoints(struct CRLDistributionPoints *mine, ushort level);

struct IssuingDistPoint
    {
    struct casn self;
    struct DistributionPointName distributionPoint;
    struct casn onlyContainsUserCerts;
    struct casn onlyContainsCACerts;
    struct ReasonFlags onlySomeReasons;
    struct casn indirectCRL;
    };

void IssuingDistPoint(struct IssuingDistPoint *mine, ushort level);

#define DeltaCRLIndicator casn

struct CRLReason
    {
    struct casn self;
    struct casn unspecified;
    struct casn keyCompromised;
    struct casn caCompromised;
    struct casn affiliationChanged;
    struct casn superseded;
    struct casn cessationOfOperation;
    struct casn certificateHold;
    struct casn certHoldRelease;
    struct casn removeFromCRL;
    };

void CRLReason(struct CRLReason *mine, ushort level);

struct ExtKeyUsageSyntax
    {
    struct casn self;
    struct casn keyPurposeId;
    };

void ExtKeyUsageSyntax(struct ExtKeyUsageSyntax *mine, ushort level);

struct SBGPIpAddrBlock
    {
    struct casn self;
    struct IPAddressFamilyA iPAddressFamilyA;
    };

void SBGPIpAddrBlock(struct SBGPIpAddrBlock *mine, ushort level);

struct RouterIdentifier
    {
    struct casn self;
    struct OwningASNumber owningASNumber;
    };

void RouterIdentifier(struct RouterIdentifier *mine, ushort level);

struct MerchantData
    {
    struct casn self;
    struct MerchantID merID;
    struct BIN merAcquirerBIN;
    struct MerNameSeq merNameSeq;
    struct CountryCode merCountry;
    struct casn merAuthFlag;
    };

void MerchantData(struct MerchantData *mine, ushort level);

#define CardCertRequired casn

struct Tunneling
    {
    struct casn self;
    struct casn tunneling;
    struct TunnelAlg tunnelAlgIDs;
    };

void Tunneling(struct Tunneling *mine, ushort level);

struct SetExtensions
    {
    struct casn self;
    struct casn iD;
    };

void SetExtensions(struct SetExtensions *mine, ushort level);

struct AuthorityInfoAccessSyntax
    {
    struct casn self;
    struct AccessDescription accessDescription;
    };

void AuthorityInfoAccessSyntax(struct AuthorityInfoAccessSyntax *mine, ushort level);

struct SBGPASNum
    {
    struct casn self;
    struct ASIdentifierChoiceA asnum;
    struct ASIdentifierChoiceA rdi;
    };

void SBGPASNum(struct SBGPASNum *mine, ushort level);

void ExtensionSetInExtension(struct casn *mine, ushort level);

struct ExtensionSetDefined
    {
    struct casn self;
    struct SubjectDirectoryAttributes subjectDirectoryAttributes;
    struct casn subjectKeyIdentifier;
    struct KeyUsage keyUsage;
    struct PrivateKeyUsagePeriod privateKeyUsagePeriod;
    struct GeneralNames subjectAltName;
    struct GeneralNames issuerAltName;
    struct BasicConstraints basicConstraints;
    struct NameConstraints nameConstraints;
    struct CertificatePolicies certificatePolicies;
    struct PolicyMappings policyMappings;
    struct PolicyConstraints policyConstraints;
    struct CRLDistributionPoints cRLDistributionPoints;
    struct AuthorityKeyId authKeyId;
    struct ExtKeyUsageSyntax extKeyUsage;
    struct CertificateType certificateType;
    struct MerchantData merchantData;
    struct casn cardCertRequired;
    struct Tunneling tunneling;
    struct SetExtensions setExtensions;
    struct AuthorityInfoAccessSyntax authorityInfoAccess;
    struct SBGPIpAddrBlock ipAddressBlock;
    struct SBGPASNum autonomousSysNum;
    struct RouterIdentifier routerId;
    struct casn other;
    };

void ExtensionSetDefined(struct ExtensionSetDefined *mine, ushort level);

void CRLExtensionSetInCRLExtension(struct casn *mine, ushort level);

struct CRLExtensionSetDefined
    {
    struct casn self;
    struct AuthorityKeyId authKeyId;
    struct GeneralNames issuerAltName;
    struct casn cRLNumber;
    struct IssuingDistPoint issuingDistributionPoint;
    struct casn deltaCRLIndicator;
    struct casn other;
    };

void CRLExtensionSetDefined(struct CRLExtensionSetDefined *mine, ushort level);

void CRLEntryExtensionSetInCRLEntryExtension(struct casn *mine, ushort level);

struct CRLEntryExtensionSetDefined
    {
    struct casn self;
    struct CRLReason reasonCode;
    struct casn invalidityDate;
    struct casn instructionCode;
    struct GeneralNames certificateIssuer;
    struct casn other;
    };

void CRLEntryExtensionSetDefined(struct CRLEntryExtensionSetDefined *mine, ushort level);

struct CRLExtension
    {
    struct casn self;
    struct casn extnID;
    struct casn critical;
    struct CRLExtensionSetDefined extnValue;
    };

void CRLExtension(struct CRLExtension *mine, ushort level);

struct CRLEntryExtension
    {
    struct casn self;
    struct casn extnID;
    struct casn critical;
    struct CRLEntryExtensionSetDefined extnValue;
    };

void CRLEntryExtension(struct CRLEntryExtension *mine, ushort level);

struct Extension
    {
    struct casn self;
    struct casn extnID;
    struct casn critical;
    struct ExtensionSetDefined extnValue;
    };

void Extension(struct Extension *mine, ushort level);

struct Extensions
    {
    struct casn self;
    struct Extension extension;
    };

void Extensions(struct Extensions *mine, ushort level);

struct CrlExtensions
    {
    struct casn self;
    struct CRLExtension cRLExtension;
    };

void CrlExtensions(struct CrlExtensions *mine, ushort level);

struct CrlEntryExtensions
    {
    struct casn self;
    struct CRLEntryExtension cRLEntryExtension;
    };

void CrlEntryExtensions(struct CrlEntryExtensions *mine, ushort level);

#endif /* extensions_h */
