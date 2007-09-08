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
package crlv2;
import Algorithms.*;
import extensions.*;
// import serial_number.*;
import name.*;
import asn.*;
public class CertificateRevocationListToBeSigned extends AsnSequence
    {
    public CrlVersion version = new CrlVersion();
    public AlgorithmIdentifier signature = new AlgorithmIdentifier();
    public Name issuer = new Name();
    public ChoiceOfTime lastUpdate = new ChoiceOfTime();
    public ChoiceOfTime nextUpdate = new ChoiceOfTime();
    public RevokedCertificatesInCertificateRevocationListToBeSigned revokedCertificates = new RevokedCertificatesInCertificateRevocationListToBeSigned();
    public CrlExtensions extensions = new CrlExtensions();
    public int constraint() { return 1; };
    public CertificateRevocationListToBeSigned()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, version, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _set_sub_flag(version.v1, (short)(AsnStatic.ASN_DEFAULT_FLAG));
        _setup(version, signature, (short)0, (int)0x0);
        _setup(signature, issuer, (short)0, (int)0x0);
        _setup(issuer, lastUpdate, (short)0, (int)0x0);
        _setup(lastUpdate, nextUpdate, (short)0, (int)0x0);
        _setup(nextUpdate, revokedCertificates, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(revokedCertificates, extensions, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA0);
        }
    public CertificateRevocationListToBeSigned set(CertificateRevocationListToBeSigned frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
