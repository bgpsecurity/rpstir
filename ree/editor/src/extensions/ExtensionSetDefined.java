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
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class ExtensionSetDefined extends AsnChoice
    {
    public SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes();
    public AsnOctetString subjectKeyIdentifier = new AsnOctetString();
    public KeyUsage keyUsage = new KeyUsage();
    public PrivateKeyUsagePeriod privateKeyUsagePeriod = new PrivateKeyUsagePeriod();
    public GeneralNames subjectAltName = new GeneralNames();
    public GeneralNames issuerAltName = new GeneralNames();
    public BasicConstraints basicConstraints = new BasicConstraints();
    public NameConstraints nameConstraints = new NameConstraints();
    public CertificatePolicies certificatePolicies = new CertificatePolicies();
    public PolicyMappings policyMappings = new PolicyMappings();
    public PolicyConstraints policyConstraints = new PolicyConstraints();
    public CRLDistributionPoints cRLDistributionPoints = new CRLDistributionPoints();
    public AuthorityKeyId authKeyId = new AuthorityKeyId();
    public ExtKeyUsageSyntax extKeyUsage = new ExtKeyUsageSyntax();
    public CertificateType certificateType = new CertificateType();
    public MerchantData merchantData = new MerchantData();
    public AsnBoolean cardCertRequired = new AsnBoolean();
    public Tunneling tunneling = new Tunneling();
    public SetExtensions setExtensions = new SetExtensions();
    public AuthorityInfoAccessSyntax authorityInfoAccess = new AuthorityInfoAccessSyntax();
    public SubjectInfoAccessSyntax subjectInfoAccess = new SubjectInfoAccessSyntax();
    public IPAddrBlocks ipAddressBlock = new IPAddrBlocks();
    public ASNum autonomousSysNum = new ASNum();
    public RouterIdentifier routerId = new RouterIdentifier();
    public AsnNotAsn1  other = new AsnNotAsn1 ();
    public ExtensionSetDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, subjectDirectoryAttributes, (short)0, (int)0x0);
        _setup(subjectDirectoryAttributes, subjectKeyIdentifier, (short)0, (int)0x0);
        _setup(subjectKeyIdentifier, keyUsage, (short)0, (int)0x0);
        _setup(keyUsage, privateKeyUsagePeriod, (short)0, (int)0x0);
        _setup(privateKeyUsagePeriod, subjectAltName, (short)0, (int)0x0);
        _setup(subjectAltName, issuerAltName, (short)0, (int)0x0);
        _setup(issuerAltName, basicConstraints, (short)0, (int)0x0);
        _setup(basicConstraints, nameConstraints, (short)0, (int)0x0);
        _setup(nameConstraints, certificatePolicies, (short)0, (int)0x0);
        _setup(certificatePolicies, policyMappings, (short)0, (int)0x0);
        _setup(policyMappings, policyConstraints, (short)0, (int)0x0);
        _setup(policyConstraints, cRLDistributionPoints, (short)0, (int)0x0);
        _setup(cRLDistributionPoints, authKeyId, (short)0, (int)0x0);
        _setup(authKeyId, extKeyUsage, (short)0, (int)0x0);
        _setup(extKeyUsage, certificateType, (short)0, (int)0x0);
        _setup(certificateType, merchantData, (short)0, (int)0x0);
        _setup(merchantData, cardCertRequired, (short)0, (int)0x0);
        _setup(cardCertRequired, tunneling, (short)0, (int)0x0);
        _setup(tunneling, setExtensions, (short)0, (int)0x0);
        _setup(setExtensions, authorityInfoAccess, (short)0, (int)0x0);
        _setup(authorityInfoAccess, subjectInfoAccess, (short)0, (int)0x0);
        _setup(subjectInfoAccess, ipAddressBlock, (short)0, (int)0x0);
        _setup(ipAddressBlock, autonomousSysNum, (short)0, (int)0x0);
        _setup(autonomousSysNum, routerId, (short)0, (int)0x0);
        _setup(routerId, other, (short)0, (int)0x0);
        }
    public ExtensionSetDefined set(ExtensionSetDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
