#ifndef _Algorithms_h
#define _Algorithms_h

#ifndef _casn_h
#include "casn.h"
#endif
#define id_infosec "2.16.840.1.101.2.1"
#define id_modules "2.16.840.1.101.2.1.0"
#define id_algorithms "2.16.840.1.101.2.1.1"
#define id_formats "2.16.840.1.101.2.1.2"
#define id_policy "2.16.840.1.101.2.1.3"
#define id_object_classes "2.16.840.1.101.2.1.4"
#define id_attributes "2.16.840.1.101.2.1.5"
#define id_sdnsSignatureAlgorithm "2.16.840.1.101.2.1.1.1"
#define id_mosaicSignatureAlgorithm "2.16.840.1.101.2.1.1.2"
#define id_sdnsConfidentialityAlgorithm "2.16.840.1.101.2.1.1.3"
#define id_mosaicConfidentialityAlgorithm "2.16.840.1.101.2.1.1.4"
#define id_sdnsIntegrityAlgorithm "2.16.840.1.101.2.1.1.5"
#define id_mosaicIntegrityAlgorithm "2.16.840.1.101.2.1.1.6"
#define id_sdnsTokenProtectionAlgorithm "2.16.840.1.101.2.1.1.7"
#define id_mosaicTokenProtectionAlgorithm "2.16.840.1.101.2.1.1.8"
#define id_sdnsKeyManagementAlgorithm "2.16.840.1.101.2.1.1.9"
#define id_mosaicKeyManagementAlgorithm "2.16.840.1.101.2.1.1.10"
#define id_sdnsKMandSigAlgorithms "2.16.840.1.101.2.1.1.11"
#define id_mosaicKMandSigAlgorithms "2.16.840.1.101.2.1.1.12"
#define id_keyEncryptionAlgorithm "2.16.840.1.101.2.1.1.22"
#define id_msp_content_type "2.16.840.1.101.2.1.2.48"
#define id_msp_rev3_content_type "2.16.840.1.101.2.1.2.42"
#define id_msp_rekey_agent_protocol "2.16.840.1.101.2.1.2.49"
#define id_rfc822_message_format "2.16.840.1.101.2.1.2.1"
#define id_empty_content "2.16.840.1.101.2.1.2.2"
#define forwarded_MSP_message_body_part "2.16.840.1.101.2.1.2.72"
#define id_sdns_security_policy_id "2.16.840.1.101.2.1.3.1"
#define id_sdns_prbac_id "2.16.840.1.101.2.1.3.2"
#define id_mosaic_prbac_id "2.16.840.1.101.2.1.3.3"
#define id_msp_user_sdns "2.16.840.1.101.2.1.4.1"
#define id_mail_list "2.16.840.1.101.2.1.4.2"
#define id_dsa_sdns "2.16.840.1.101.2.1.4.3"
#define id_ca_sdns "2.16.840.1.101.2.1.4.4"
#define id_crls_sdns "2.16.840.1.101.2.1.4.5"
#define id_msp_user_mosaic "2.16.840.1.101.2.1.4.6"
#define id_dsa_mosaic "2.16.840.1.101.2.1.4.7"
#define id_ca_mosaic "2.16.840.1.101.2.1.4.8"
#define id_sdnsKeyManagementCertificate "2.16.840.1.101.2.1.5.1"
#define id_sdnsUserSignatureCertificate "2.16.840.1.101.2.1.5.2"
#define id_sdnsKMandSigCertificate "2.16.840.1.101.2.1.5.3"
#define id_mosaicKeyManagementCertificate "2.16.840.1.101.2.1.5.4"
#define id_mosaicKMandSigCertificate "2.16.840.1.101.2.1.5.5"
#define id_mosaicUserSignatureCertificate "2.16.840.1.101.2.1.5.6"
#define id_mosaicCASignatureCertificate "2.16.840.1.101.2.1.5.7"
#define id_sdnsCASignatureCertificate "2.16.840.1.101.2.1.5.8"
#define id_auxiliaryVector "2.16.840.1.101.2.1.5.10"
#define id_mlReceiptPolicy "2.16.840.1.101.2.1.5.11"
#define id_mlMembership "2.16.840.1.101.2.1.5.12"
#define id_mlAdministrators "2.16.840.1.101.2.1.5.13"
#define id_mlid "2.16.840.1.101.2.1.5.14"
#define id_janUKMs "2.16.840.1.101.2.1.5.20"
#define id_febUKMs "2.16.840.1.101.2.1.5.21"
#define id_marUKMs "2.16.840.1.101.2.1.5.22"
#define id_aprUKMs "2.16.840.1.101.2.1.5.23"
#define id_mayUKMs "2.16.840.1.101.2.1.5.24"
#define id_junUKMs "2.16.840.1.101.2.1.5.25"
#define id_julUKMs "2.16.840.1.101.2.1.5.26"
#define id_augUKMs "2.16.840.1.101.2.1.5.27"
#define id_sepUKMs "2.16.840.1.101.2.1.5.28"
#define id_octUKMs "2.16.840.1.101.2.1.5.29"
#define id_novUKMs "2.16.840.1.101.2.1.5.30"
#define id_decUKMs "2.16.840.1.101.2.1.5.31"
#define id_metaSDNScrl "2.16.840.1.101.2.1.5.40"
#define id_sdnsCRL "2.16.840.1.101.2.1.5.41"
#define id_metaSDNSsignatureCRL "2.16.840.1.101.2.1.5.42"
#define id_SDNSsignatureCRL "2.16.840.1.101.2.1.5.43"
#define id_sdnsCertificateRevocationList "2.16.840.1.101.2.1.5.44"
#define id_mosaicCertificateRevocationList "2.16.840.1.101.2.1.5.45"
#define id_mosaicKRL "2.16.840.1.101.2.1.5.46"
#define id_mlExemptedAddressProcessor "2.16.840.1.101.2.1.5.47"
#define secsig_algorithm "1.3.14.3.2"
#define id_secsig_MD4withRSA "1.3.14.3.2.2"
#define id_secsig_MD5withRSA "1.3.14.3.2.3"
#define id_secsig_MD4withRSAEncryption "1.3.14.3.2.4"
#define id_secsig_DES_ECB "1.3.14.3.2.6"
#define id_secsig_DES_CBC "1.3.14.3.2.7"
#define id_secsig_DES_OFB "1.3.14.3.2.8"
#define id_secsig_DES_CFB "1.3.14.3.2.9"
#define id_secsig_DES_MAC "1.3.14.3.2.10"
#define id_secsig_RSA "1.3.14.3.2.11"
#define id_secsig_DSA "1.3.14.3.2.12"
#define id_secsig_DSAwithSHA "1.3.14.3.2.13"
#define id_secsig_MDC_2withRSASignature "1.3.14.3.2.14"
#define id_secsig_SHAwithRSASignature "1.3.14.3.2.15"
#define id_secsig_diffieHellman "1.3.14.3.2.16"
#define id_secsig_DES_EDE "1.3.14.3.2.17"
#define id_secsig_SHA "1.3.14.3.2.18"
#define id_secsig_MDC_2 "1.3.14.3.2.19"
#define id_secsig_DSA_Common "1.3.14.3.2.20"
#define id_secsig_DSACommonWithSHA "1.3.14.3.2.21"
#define id_secsig_MD2withRSASignature "1.3.14.3.2.22"
#define id_secsig_MD5withRSASignature "1.3.14.3.2.23"
#define id_secsig_DSAwithSHA_1 "1.3.14.3.2.27"
#define id_secsig_SHA_1withRSASignature "1.3.14.3.2.29"
#define rsadsi "1.2.840.113549"
#define rsadsi_digestAlgorithm "1.2.840.113549.2"
#define rsadsi_encryptionAlgorithm "1.2.840.113549.3"
#define pkcs "1.2.840.113549.1"
#define pkcs_1 "1.2.840.113549.1.1"
#define pkcs_3 "1.2.840.113549.1.3"
#define id_rsadsi_MD2 "1.2.840.113549.2.2"
#define id_rsadsi_MD4 "1.2.840.113549.2.4"
#define id_rsadsi_MD5 "1.2.840.113549.2.5"
#define id_rsadsi_MD2withRSAEncryption "1.2.840.113549.1.1.2"
#define id_rsadsi_MD5withRSAEncryption "1.2.840.113549.1.1.4"
#define id_rsadsi_rsaEncryption "1.2.840.113549.1.1.1"
#define id_rsadsi_diffieHellman "1.2.840.113549.1.3.1"
#define id_rsadsi_RC2_CBC "1.2.840.113549.3.2"
#define id_rsadsi_RC4 "1.2.840.113549.3.4"
#define id_sha_1WithRSAEncryption "1.2.840.113549.1.1.5"
#define dssig_algorithm "1.3.14.7.2"
#define dssig_encryption_algorithm "1.3.14.7.2.1"
#define dssig_signature_algorithm "1.3.14.7.2.3"
#define id_dssig_ElGamal "1.3.14.7.2.1.1"
#define id_dssig_MD2withRSA "1.3.14.7.2.3.1"
#define id_dssig_MD2withElGamal "1.3.14.7.2.3.2"
#define id_x9 "1.2.840.10040.4"
#define id_dsa "1.2.840.10040.4.1"
#define id_dsa_with_sha1 "1.2.840.10040.4.3"
#define dnpublicnumber "1.2.840.10046.1"
#define us "840"
#define ansi_x942 "10046"

struct Dss_Parms
    {
    struct casn self;
    struct casn p;
    struct casn q;
    struct casn g;
    };

void Dss_Parms(struct Dss_Parms *mine, ushort level);

struct Kea_Parms
    {
    struct casn self;
    struct casn p;
    struct casn q;
    struct casn g;
    };

void Kea_Parms(struct Kea_Parms *mine, ushort level);

struct Different_Parms
    {
    struct casn self;
    struct Kea_Parms keaparms;
    struct Dss_Parms dssparms;
    };

void Different_Parms(struct Different_Parms *mine, ushort level);

struct Common_Parms
    {
    struct casn self;
    struct casn p;
    struct casn q;
    struct casn g;
    };

void Common_Parms(struct Common_Parms *mine, ushort level);

#define IV casn

#define NumberOfBits casn

struct DSAParameters
    {
    struct casn self;
    struct casn prime1;
    struct casn prime2;
    struct casn base;
    };

void DSAParameters(struct DSAParameters *mine, ushort level);

struct Kea_Dss_Parms
    {
    struct casn self;
    struct Different_Parms diffParms;
    struct Common_Parms commonParms;
    };

void Kea_Dss_Parms(struct Kea_Dss_Parms *mine, ushort level);

struct Skipjack_Parm
    {
    struct casn self;
    struct casn initvector;
    };

void Skipjack_Parm(struct Skipjack_Parm *mine, ushort level);

struct DiffieHellmanParameters
    {
    struct casn self;
    struct casn prime;
    struct casn base;
    struct casn privateValueLength;
    };

void DiffieHellmanParameters(struct DiffieHellmanParameters *mine, ushort level);

#define DSA_Common casn

struct FBParameter
    {
    struct casn self;
    struct casn iv;
    struct casn numberOfBits;
    };

void FBParameter(struct FBParameter *mine, ushort level);

void AlgorithmTableInAlgorithmIdentifier(struct casn *mine, ushort level);

struct AlgorithmTableDefined
    {
    struct casn self;
    struct casn sdnsSignatureAlgorithm;
    struct Dss_Parms mosaicSignatureAlgorithm;
    struct casn sdnsConfidentialityAlgorithm;
    struct Skipjack_Parm mosaicConfidentialityAlgorithm;
    struct casn sdnsIntegrityAlgorithm;
    struct casn mosaicIntegrityAlgorithm;
    struct casn sdnsTokenProtectionAlgorithm;
    struct casn mosaicTokenProtectionAlgorithm;
    struct casn sdnsKeyManagementAlgorithm;
    struct Kea_Parms mosaicKeyManagementAlgorithm;
    struct casn sdnsKMandSigAlgorithms;
    struct Kea_Dss_Parms mosaicKMandSigAlgorithms;
    struct casn secsig_MD4withRSA;
    struct casn secsig_MD5withRSA;
    struct casn secsig_MD4withRSAEncryption;
    struct casn secsig_DES_ECB;
    struct casn secsig_DES_CBC;
    struct FBParameter secsig_DES_OFB;
    struct FBParameter secsig_DES_CFB;
    struct casn secsig_DES_MAC;
    struct casn secsig_RSA;
    struct DSAParameters secsig_DSA;
    struct DSAParameters secsig_DSAwithSHA;
    struct DSAParameters secsig_DSAwithSHA_1;
    struct casn secsig_MDC_2withRSASignature;
    struct casn secsig_SHAwithRSASignature;
    struct casn secsig_SHA_1withRSASignature;
    struct casn secsig_diffieHellman;
    struct casn secsig_DES_EDE;
    struct casn secsig_SHA;
    struct casn secsig_MDC_2;
    struct casn secsig_DSA_Common;
    struct casn secsig_DSACommonWithSHA;
    struct casn secsig_MD2withRSASignature;
    struct casn secsig_MD5withRSASignature;
    struct casn rsadsi_MD2;
    struct casn rsadsi_MD4;
    struct casn rsadsi_MD5;
    struct casn rsadsi_MD2withRSAEncryption;
    struct casn rsadsi_MD5withRSAEncryption;
    struct casn rsadsi_rsaEncryption;
    struct DiffieHellmanParameters rsadsi_diffieHellman;
    struct casn rsadsi_RC2_CBC;
    struct casn rsadsi_RC4;
    struct casn dssig_ElGamal;
    struct casn dssig_MD2withRSA;
    struct casn dssig_MD2withElGamal;
    struct DSAParameters dsa;
    struct casn dsa_with_sha1;
    struct casn rsadsi_SHA_1WithRSAEncryption;
    struct casn unknown;
    };

void AlgorithmTableDefined(struct AlgorithmTableDefined *mine, ushort level);

struct DSASignature
    {
    struct casn self;
    struct casn arr;
    struct casn ess;
    };

void DSASignature(struct DSASignature *mine, ushort level);

struct AlgorithmIdentifier
    {
    struct casn self;
    struct casn algorithm;
    struct AlgorithmTableDefined parameters;
    };

void AlgorithmIdentifier(struct AlgorithmIdentifier *mine, ushort level);

#define KEA_Parms_Id casn

#endif /* Algorithms_h */
