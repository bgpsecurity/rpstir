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
package Algorithms;
import asn.*;
public class AlgorithmTableDefined extends AsnChoice
    {
    public AsnNone sdnsSignatureAlgorithm = new AsnNone();
    public Dss_Parms mosaicSignatureAlgorithm = new Dss_Parms();
    public AsnNone sdnsConfidentialityAlgorithm = new AsnNone();
    public Skipjack_Parm mosaicConfidentialityAlgorithm = new Skipjack_Parm();
    public AsnNone sdnsIntegrityAlgorithm = new AsnNone();
    public AsnNone mosaicIntegrityAlgorithm = new AsnNone();
    public AsnNone sdnsTokenProtectionAlgorithm = new AsnNone();
    public AsnNone mosaicTokenProtectionAlgorithm = new AsnNone();
    public AsnNone sdnsKeyManagementAlgorithm = new AsnNone();
    public Kea_Parms mosaicKeyManagementAlgorithm = new Kea_Parms();
    public AsnNone sdnsKMandSigAlgorithms = new AsnNone();
    public Kea_Dss_Parms mosaicKMandSigAlgorithms = new Kea_Dss_Parms();
    public AsnNone secsig_MD4withRSA = new AsnNone();
    public AsnNone secsig_MD5withRSA = new AsnNone();
    public AsnNull secsig_MD4withRSAEncryption = new AsnNull();
    public AsnNone secsig_DES_ECB = new AsnNone();
    public AsnOctetString secsig_DES_CBC = new AsnOctetString();
    public FBParameter secsig_DES_OFB = new FBParameter();
    public FBParameter secsig_DES_CFB = new FBParameter();
    public AsnInteger secsig_DES_MAC = new AsnInteger();
    public AsnNone secsig_RSA = new AsnNone();
    public DSAParameters secsig_DSA = new DSAParameters();
    public DSAParameters secsig_DSAwithSHA = new DSAParameters();
    public DSAParameters secsig_DSAwithSHA_1 = new DSAParameters();
    public AsnNone secsig_MDC_2withRSASignature = new AsnNone();
    public AsnNone secsig_SHAwithRSASignature = new AsnNone();
    public AsnNone secsig_SHA_1withRSASignature = new AsnNone();
    public AsnNone secsig_diffieHellman = new AsnNone();
    public AsnNone secsig_DES_EDE = new AsnNone();
    public AsnNone secsig_SHA = new AsnNone();
    public AsnNone secsig_MDC_2 = new AsnNone();
    public AsnNone secsig_DSA_Common = new AsnNone();
    public AsnNull secsig_DSACommonWithSHA = new AsnNull();
    public AsnNone secsig_MD2withRSASignature = new AsnNone();
    public AsnNone secsig_MD5withRSASignature = new AsnNone();
    public AsnNull rsadsi_MD2 = new AsnNull();
    public AsnNull rsadsi_MD4 = new AsnNull();
    public AsnNull rsadsi_MD5 = new AsnNull();
    public AsnNull rsadsi_md2WithRSAEncryption = new AsnNull();
    public AsnNull rsadsi_md5WithRSAEncryption = new AsnNull();
    public AsnNull rsadsi_sha_1WithRSAEncryption = new AsnNull();
    public AsnNull rsadsi_rsaEncryption = new AsnNull();
    public DiffieHellmanParameters rsadsi_diffieHellman = new DiffieHellmanParameters();
    public AsnNone rsadsi_RC2_CBC = new AsnNone();
    public AsnNone rsadsi_RC4 = new AsnNone();
    public AsnNone dssig_ElGamal = new AsnNone();
    public AsnNone dssig_MD2withRSA = new AsnNone();
    public AsnNone dssig_MD2withElGamal = new AsnNone();
    public DSAParameters dsa = new DSAParameters();
    public AsnNone dsa_with_sha1 = new AsnNone();
    public AsnNull rsadsi_sha256WithRSAEncryption = new AsnNull();
    public AsnAny unknown = new AsnAny();
    public AlgorithmTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, sdnsSignatureAlgorithm, (short)0, (int)0x0);
        _setup(sdnsSignatureAlgorithm, mosaicSignatureAlgorithm, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(mosaicSignatureAlgorithm, sdnsConfidentialityAlgorithm, (short)0, (int)0x0);
        _setup(sdnsConfidentialityAlgorithm, mosaicConfidentialityAlgorithm, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(mosaicConfidentialityAlgorithm, sdnsIntegrityAlgorithm, (short)0, (int)0x0);
        _setup(sdnsIntegrityAlgorithm, mosaicIntegrityAlgorithm, (short)0, (int)0x0);
        _setup(mosaicIntegrityAlgorithm, sdnsTokenProtectionAlgorithm, (short)0, (int)0x0);
        _setup(sdnsTokenProtectionAlgorithm, mosaicTokenProtectionAlgorithm, (short)0, (int)0x0);
        _setup(mosaicTokenProtectionAlgorithm, sdnsKeyManagementAlgorithm, (short)0, (int)0x0);
        _setup(sdnsKeyManagementAlgorithm, mosaicKeyManagementAlgorithm, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(mosaicKeyManagementAlgorithm, sdnsKMandSigAlgorithms, (short)0, (int)0x0);
        _setup(sdnsKMandSigAlgorithms, mosaicKMandSigAlgorithms, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(mosaicKMandSigAlgorithms, secsig_MD4withRSA, (short)0, (int)0x0);
        _setup(secsig_MD4withRSA, secsig_MD5withRSA, (short)0, (int)0x0);
        _setup(secsig_MD5withRSA, secsig_MD4withRSAEncryption, (short)0, (int)0x0);
        _setup(secsig_MD4withRSAEncryption, secsig_DES_ECB, (short)0, (int)0x0);
        _setup(secsig_DES_ECB, secsig_DES_CBC, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DES_CBC, secsig_DES_OFB, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DES_OFB, secsig_DES_CFB, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DES_CFB, secsig_DES_MAC, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DES_MAC, secsig_RSA, (short)0, (int)0x0);
        _setup(secsig_RSA, secsig_DSA, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DSA, secsig_DSAwithSHA, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DSAwithSHA, secsig_DSAwithSHA_1, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DSAwithSHA_1, secsig_MDC_2withRSASignature, (short)0, (int)0x0);
        _setup(secsig_MDC_2withRSASignature, secsig_SHAwithRSASignature, (short)0, (int)0x0);
        _setup(secsig_SHAwithRSASignature, secsig_SHA_1withRSASignature, (short)0, (int)0x0);
        _setup(secsig_SHA_1withRSASignature, secsig_diffieHellman, (short)0, (int)0x0);
        _setup(secsig_diffieHellman, secsig_DES_EDE, (short)0, (int)0x0);
        _setup(secsig_DES_EDE, secsig_SHA, (short)0, (int)0x0);
        _setup(secsig_SHA, secsig_MDC_2, (short)0, (int)0x0);
        _setup(secsig_MDC_2, secsig_DSA_Common, (short)0, (int)0x0);
        _setup(secsig_DSA_Common, secsig_DSACommonWithSHA, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(secsig_DSACommonWithSHA, secsig_MD2withRSASignature, (short)0, (int)0x0);
        _setup(secsig_MD2withRSASignature, secsig_MD5withRSASignature, (short)0, (int)0x0);
        _setup(secsig_MD5withRSASignature, rsadsi_MD2, (short)0, (int)0x0);
        _setup(rsadsi_MD2, rsadsi_MD4, (short)0, (int)0x0);
        _setup(rsadsi_MD4, rsadsi_MD5, (short)0, (int)0x0);
        _setup(rsadsi_MD5, rsadsi_md2WithRSAEncryption, (short)0, (int)0x0);
        _setup(rsadsi_md2WithRSAEncryption, rsadsi_md5WithRSAEncryption, (short)0, (int)0x0);
        _setup(rsadsi_md5WithRSAEncryption, rsadsi_sha_1WithRSAEncryption, (short)0, (int)0x0);
        _setup(rsadsi_sha_1WithRSAEncryption, rsadsi_rsaEncryption, (short)0, (int)0x0);
        _setup(rsadsi_rsaEncryption, rsadsi_diffieHellman, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(rsadsi_diffieHellman, rsadsi_RC2_CBC, (short)0, (int)0x0);
        _setup(rsadsi_RC2_CBC, rsadsi_RC4, (short)0, (int)0x0);
        _setup(rsadsi_RC4, dssig_ElGamal, (short)0, (int)0x0);
        _setup(dssig_ElGamal, dssig_MD2withRSA, (short)0, (int)0x0);
        _setup(dssig_MD2withRSA, dssig_MD2withElGamal, (short)0, (int)0x0);
        _setup(dssig_MD2withElGamal, dsa, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(dsa, dsa_with_sha1, (short)0, (int)0x0);
        _setup(dsa_with_sha1, rsadsi_sha256WithRSAEncryption, (short)0, (int)0x0); 
        _setup(rsadsi_sha256WithRSAEncryption, unknown, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AlgorithmTableDefined set(AlgorithmTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
