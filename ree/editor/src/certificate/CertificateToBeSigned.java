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
package certificate;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import extensions.*;
import asn.*;
public class CertificateToBeSigned extends AsnSequence
    {
    public Version version = new Version();
    public AsnInteger serialNumber = new AsnInteger();
    public AlgorithmIdentifier signature = new AlgorithmIdentifier();
    public Name issuer = new Name();
    public Validity validity = new Validity();
    public Name subject = new Name();
    public SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    public AsnBitString issuerUniqueID = new AsnBitString();
    public AsnBitString subjectUniqueID = new AsnBitString();
    public Extensions extensions = new Extensions();
    public int constraint() { return 1; };
    public CertificateToBeSigned()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, version, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA0);
        _set_sub_flag(version.v1, (short)(AsnStatic.ASN_DEFAULT_FLAG));
        _setup(version, serialNumber, (short)0, (int)0x0);
        _setup(serialNumber, signature, (short)0, (int)0x0);
        _setup(signature, issuer, (short)0, (int)0x0);
        _setup(issuer, validity, (short)0, (int)0x0);
        _setup(validity, subject, (short)0, (int)0x0);
        _setup(subject, subjectPublicKeyInfo, (short)0, (int)0x0);
        _setup(subjectPublicKeyInfo, issuerUniqueID, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(issuerUniqueID, subjectUniqueID, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        _setup(subjectUniqueID, extensions, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA3);
        }
    public CertificateToBeSigned set(CertificateToBeSigned frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
