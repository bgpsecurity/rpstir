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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
package extensions;
public class ExtensionsStatic
    {
    public static final int OPTIONAL_EXTENSION = 0;
    public static final int MANDATORY_EXTENSION = 1;
    public static final int DEPRECATED_EXTENSION = 2;
    public static final int NON_CRITICAL_EXTENSION = 0;
    public static final int CRITICAL_EXTENSION = 1;
    public static final int ub_countryName = 50;
    public static final int ub_cityName = 50;
    public static final int ub_merName = 25;
    public static final int ub_postalCode = 14;
    public static final int ub_stateProvince = 25;
    public static final int ub_terseStatement = 2048;
    public static final int ub_RFC1766_language = 35;
    public static final int ub_MerchantID = 30;
    public static final int ub_url = 512;
    public static final String id_ce = "2.5.29";
    public static final String id_subjectDirectoryAttributes = "2.5.29.9";
    public static final String id_subjectKeyIdentifier = "2.5.29.14";
    public static final String id_keyUsage = "2.5.29.15";
    public static final String id_privateKeyUsagePeriod = "2.5.29.16";
    public static final String id_subjectAltName = "2.5.29.17";
    public static final String id_issuerAltName = "2.5.29.18";
    public static final String id_basicConstraints = "2.5.29.19";
    public static final String id_cRLNumber = "2.5.29.20";
    public static final String id_reasonCode = "2.5.29.21";
    public static final String id_instructionCode = "2.5.29.23";
    public static final String id_invalidityDate = "2.5.29.24";
    public static final String id_deltaCRLIndicator = "2.5.29.27";
    public static final String id_issuingDistributionPoint = "2.5.29.28";
    public static final String id_certificateIssuer = "2.5.29.29";
    public static final String id_nameConstraints = "2.5.29.30";
    public static final String id_cRLDistributionPoints = "2.5.29.31";
    public static final String id_certificatePolicies = "2.5.29.32";
    public static final String id_policyMappings = "2.5.29.33";
    public static final String id_authKeyId = "2.5.29.35";
    public static final String id_policyConstraints = "2.5.29.36";
    public static final String id_extKeyUsage = "2.5.29.37";
    public static final String id_set_certExt = "2.23.42.7";
    public static final String id_set_hashedRootKey = "2.23.42.7.0";
    public static final String id_set_certificateType = "2.23.42.7.1";
    public static final String id_set_merchantData = "2.23.42.7.2";
    public static final String id_set_cardCertRequired = "2.23.42.7.3";
    public static final String id_set_tunneling = "2.23.42.7.4";
    public static final String id_set_setExtensions = "2.23.42.7.5";
    public static final String id_set_setQualifier = "2.23.42.7.6";
    public static final String id_pkix = "1.3.6.1.5.5.7";
    public static final String id_pe = "1.3.6.1.5.5.7.1";
    public static final String id_pkix_qt = "1.3.6.1.5.5.7.2";
    public static final String id_pkix_kp = "1.3.6.1.5.5.7.3";
    public static final String id_pkix_it = "1.3.6.1.5.5.7.4";
    public static final String id_ad = "1.3.6.1.5.5.7.48";
    public static final String id_pe_authorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    public static final String id_pe_subjectInfoAccess = "1.3.6.1.5.5.7.1.11";
    public static final String id_pkix_cps = "1.3.6.1.5.5.7.2.1";
    public static final String id_pkix_unotice = "1.3.6.1.5.5.7.2.2";
    public static final String id_pkix_serverAuth = "1.3.6.1.5.5.7.3.1";
    public static final String id_pkix_clientAuth = "1.3.6.1.5.5.7.3.2";
    public static final String id_pkix_codeSigning = "1.3.6.1.5.5.7.3.3";
    public static final String id_pkix_emailProtection = "1.3.6.1.5.5.7.3.4";
    public static final String id_pkix_ipsecEndSystem = "1.3.6.1.5.5.7.3.5";
    public static final String id_pkix_ipsecTunnel = "1.3.6.1.5.5.7.3.6";
    public static final String id_pkix_ipsecUser = "1.3.6.1.5.5.7.3.7";
    public static final String id_pkix_timeStamping = "1.3.6.1.5.5.7.3.8";
    public static final String id_pkix_caProtEncCert = "1.3.6.1.5.5.7.4.1";
    public static final String id_pkix_signKeyPairTypes = "1.3.6.1.5.5.7.4.2";
    public static final String id_pkix_encKeyPairTypes = "1.3.6.1.5.5.7.4.3";
    public static final String id_pkix_preferredSymmAlg = "1.3.6.1.5.5.7.4.4";
    public static final String id_pkix_caKeyUpdateInfo = "1.3.6.1.5.5.7.4.5";
    public static final String id_pkix_currentCRL = "1.3.6.1.5.5.7.4.6";
    public static final String id_pkix_ocsp = "1.3.6.1.5.5.7.48.1";
    public static final String id_ad_caIssuers = "1.3.6.1.5.5.7.48.2";
    public static final String id_ad_caRepository = "1.3.6.1.5.5.7.48.5";
    public static final String id_pe_ipAddrBlocks = "1.3.6.1.5.5.7.1.7";
    public static final String id_pe_autonomousSysIds = "1.3.6.1.5.5.7.1.8";
    public static final String id_pe_routerIdentifier = "1.3.6.1.5.5.7.1.9";
    }
