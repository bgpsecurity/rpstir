/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
package Algorithms;
public class AlgorithmsStatic
    {
    public static final String id_infosec = "2.16.840.1.101.2.1";
    public static final String id_modules = "2.16.840.1.101.2.1.0";
    public static final String id_algorithms = "2.16.840.1.101.2.1.1";
    public static final String id_formats = "2.16.840.1.101.2.1.2";
    public static final String id_policy = "2.16.840.1.101.2.1.3";
    public static final String id_object_classes = "2.16.840.1.101.2.1.4";
    public static final String id_attributes = "2.16.840.1.101.2.1.5";
    public static final String id_sdnsSignatureAlgorithm = "2.16.840.1.101.2.1.1.1";
    public static final String id_mosaicSignatureAlgorithm = "2.16.840.1.101.2.1.1.2";
    public static final String id_sdnsConfidentialityAlgorithm = "2.16.840.1.101.2.1.1.3";
    public static final String id_mosaicConfidentialityAlgorithm = "2.16.840.1.101.2.1.1.4";
    public static final String id_sdnsIntegrityAlgorithm = "2.16.840.1.101.2.1.1.5";
    public static final String id_mosaicIntegrityAlgorithm = "2.16.840.1.101.2.1.1.6";
    public static final String id_sdnsTokenProtectionAlgorithm = "2.16.840.1.101.2.1.1.7";
    public static final String id_mosaicTokenProtectionAlgorithm = "2.16.840.1.101.2.1.1.8";
    public static final String id_sdnsKeyManagementAlgorithm = "2.16.840.1.101.2.1.1.9";
    public static final String id_mosaicKeyManagementAlgorithm = "2.16.840.1.101.2.1.1.10";
    public static final String id_sdnsKMandSigAlgorithms = "2.16.840.1.101.2.1.1.11";
    public static final String id_mosaicKMandSigAlgorithms = "2.16.840.1.101.2.1.1.12";
    public static final String id_keyEncryptionAlgorithm = "2.16.840.1.101.2.1.1.22";
    public static final String id_msp_content_type = "2.16.840.1.101.2.1.2.48";
    public static final String id_msp_rev3_content_type = "2.16.840.1.101.2.1.2.42";
    public static final String id_msp_rekey_agent_protocol = "2.16.840.1.101.2.1.2.49";
    public static final String id_rfc822_message_format = "2.16.840.1.101.2.1.2.1";
    public static final String id_empty_content = "2.16.840.1.101.2.1.2.2";
    public static final String forwarded_MSP_message_body_part = "2.16.840.1.101.2.1.2.72";
    public static final String id_sdns_security_policy_id = "2.16.840.1.101.2.1.3.1";
    public static final String id_sdns_prbac_id = "2.16.840.1.101.2.1.3.2";
    public static final String id_mosaic_prbac_id = "2.16.840.1.101.2.1.3.3";
    public static final String id_msp_user_sdns = "2.16.840.1.101.2.1.4.1";
    public static final String id_mail_list = "2.16.840.1.101.2.1.4.2";
    public static final String id_dsa_sdns = "2.16.840.1.101.2.1.4.3";
    public static final String id_ca_sdns = "2.16.840.1.101.2.1.4.4";
    public static final String id_crls_sdns = "2.16.840.1.101.2.1.4.5";
    public static final String id_msp_user_mosaic = "2.16.840.1.101.2.1.4.6";
    public static final String id_dsa_mosaic = "2.16.840.1.101.2.1.4.7";
    public static final String id_ca_mosaic = "2.16.840.1.101.2.1.4.8";
    public static final String id_sdnsKeyManagementCertificate = "2.16.840.1.101.2.1.5.1";
    public static final String id_sdnsUserSignatureCertificate = "2.16.840.1.101.2.1.5.2";
    public static final String id_sdnsKMandSigCertificate = "2.16.840.1.101.2.1.5.3";
    public static final String id_mosaicKeyManagementCertificate = "2.16.840.1.101.2.1.5.4";
    public static final String id_mosaicKMandSigCertificate = "2.16.840.1.101.2.1.5.5";
    public static final String id_mosaicUserSignatureCertificate = "2.16.840.1.101.2.1.5.6";
    public static final String id_mosaicCASignatureCertificate = "2.16.840.1.101.2.1.5.7";
    public static final String id_sdnsCASignatureCertificate = "2.16.840.1.101.2.1.5.8";
    public static final String id_auxiliaryVector = "2.16.840.1.101.2.1.5.10";
    public static final String id_mlReceiptPolicy = "2.16.840.1.101.2.1.5.11";
    public static final String id_mlMembership = "2.16.840.1.101.2.1.5.12";
    public static final String id_mlAdministrators = "2.16.840.1.101.2.1.5.13";
    public static final String id_mlid = "2.16.840.1.101.2.1.5.14";
    public static final String id_janUKMs = "2.16.840.1.101.2.1.5.20";
    public static final String id_febUKMs = "2.16.840.1.101.2.1.5.21";
    public static final String id_marUKMs = "2.16.840.1.101.2.1.5.22";
    public static final String id_aprUKMs = "2.16.840.1.101.2.1.5.23";
    public static final String id_mayUKMs = "2.16.840.1.101.2.1.5.24";
    public static final String id_junUKMs = "2.16.840.1.101.2.1.5.25";
    public static final String id_julUKMs = "2.16.840.1.101.2.1.5.26";
    public static final String id_augUKMs = "2.16.840.1.101.2.1.5.27";
    public static final String id_sepUKMs = "2.16.840.1.101.2.1.5.28";
    public static final String id_octUKMs = "2.16.840.1.101.2.1.5.29";
    public static final String id_novUKMs = "2.16.840.1.101.2.1.5.30";
    public static final String id_decUKMs = "2.16.840.1.101.2.1.5.31";
    public static final String id_metaSDNScrl = "2.16.840.1.101.2.1.5.40";
    public static final String id_sdnsCRL = "2.16.840.1.101.2.1.5.41";
    public static final String id_metaSDNSsignatureCRL = "2.16.840.1.101.2.1.5.42";
    public static final String id_SDNSsignatureCRL = "2.16.840.1.101.2.1.5.43";
    public static final String id_sdnsCertificateRevocationList = "2.16.840.1.101.2.1.5.44";
    public static final String id_mosaicCertificateRevocationList = "2.16.840.1.101.2.1.5.45";
    public static final String id_mosaicKRL = "2.16.840.1.101.2.1.5.46";
    public static final String id_mlExemptedAddressProcessor = "2.16.840.1.101.2.1.5.47";
    public static final String secsig_algorithm = "1.3.14.3.2";
    public static final String id_secsig_MD4withRSA = "1.3.14.3.2.2";
    public static final String id_secsig_MD5withRSA = "1.3.14.3.2.3";
    public static final String id_secsig_MD4withRSAEncryption = "1.3.14.3.2.4";
    public static final String id_secsig_DES_ECB = "1.3.14.3.2.6";
    public static final String id_secsig_DES_CBC = "1.3.14.3.2.7";
    public static final String id_secsig_DES_OFB = "1.3.14.3.2.8";
    public static final String id_secsig_DES_CFB = "1.3.14.3.2.9";
    public static final String id_secsig_DES_MAC = "1.3.14.3.2.10";
    public static final String id_secsig_RSA = "1.3.14.3.2.11";
    public static final String id_secsig_DSA = "1.3.14.3.2.12";
    public static final String id_secsig_DSAwithSHA = "1.3.14.3.2.13";
    public static final String id_secsig_MDC_2withRSASignature = "1.3.14.3.2.14";
    public static final String id_secsig_SHAwithRSASignature = "1.3.14.3.2.15";
    public static final String id_secsig_diffieHellman = "1.3.14.3.2.16";
    public static final String id_secsig_DES_EDE = "1.3.14.3.2.17";
    public static final String id_secsig_SHA = "1.3.14.3.2.18";
    public static final String id_secsig_MDC_2 = "1.3.14.3.2.19";
    public static final String id_secsig_DSA_Common = "1.3.14.3.2.20";
    public static final String id_secsig_DSACommonWithSHA = "1.3.14.3.2.21";
    public static final String id_secsig_MD2withRSASignature = "1.3.14.3.2.22";
    public static final String id_secsig_MD5withRSASignature = "1.3.14.3.2.23";
    public static final String id_secsig_DSAwithSHA_1 = "1.3.14.3.2.27";
    public static final String id_secsig_SHA_1withRSASignature = "1.3.14.3.2.29";
    public static final String rsadsi = "1.2.840.113549";
    public static final String us = "840";
    public static final String rsadsi_digestAlgorithm = "1.2.840.113549.2";
    public static final String rsadsi_encryptionAlgorithm = "1.2.840.113549.3";
    public static final String pkcs = "1.2.840.113549.1";
    public static final String pkcs_1 = "1.2.840.113549.1.1";
    public static final String pkcs_3 = "1.2.840.113549.1.3";
    public static final String id_rsadsi_MD2 = "1.2.840.113549.2.2";
    public static final String id_rsadsi_MD4 = "1.2.840.113549.2.4";
    public static final String id_rsadsi_MD5 = "1.2.840.113549.2.5";
    public static final String id_rsadsi_rsaEncryption = "1.2.840.113549.1.1.1";
    public static final String id_md2WithRSAEncryption = "1.2.840.113549.1.1.2";
    public static final String id_md5WithRSAEncryption = "1.2.840.113549.1.1.4";
    public static final String id_sha_1WithRSAEncryption = "1.2.840.113549.1.1.5";
    public static final String id_sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
    public static final String id_sha512WithRSAEncryption = "1.2.840.113549.1.1.13";
    public static final String id_rsadsi_diffieHellman = "1.2.840.113549.1.3.1";
    public static final String id_rsadsi_RC2_CBC = "1.2.840.113549.3.2";
    public static final String id_rsadsi_RC4 = "1.2.840.113549.3.4";
    public static final String dssig_algorithm = "1.3.14.7.2";
    public static final String dssig_encryption_algorithm = "1.3.14.7.2.1";
    public static final String dssig_signature_algorithm = "1.3.14.7.2.3";
    public static final String id_dssig_ElGamal = "1.3.14.7.2.1.1";
    public static final String id_dssig_MD2withRSA = "1.3.14.7.2.3.1";
    public static final String id_dssig_MD2withElGamal = "1.3.14.7.2.3.2";
    public static final String id_x9 = "1.2.840.10040.4";
    public static final String id_dsa = "1.2.840.10040.4.1";
    public static final String id_dsa_with_sha1 = "1.2.840.10040.4.3";
    public static final String dnpublicnumber = "1.2.840.10046.1";
    public static final String ansi_x942 = "10046";
    }
