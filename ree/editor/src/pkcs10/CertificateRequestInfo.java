/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class CertificateRequestInfo extends AsnSequence
    {
    public Version version = new Version();
    public Name subject = new Name();
    public SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    public Attributes attributes = new Attributes();
    public CertificateRequestInfo()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, version, (short)0, (int)0x0);
        _setup(version, subject, (short)0, (int)0x0);
        _setup(subject, subjectPublicKeyInfo, (short)0, (int)0x0);
        _setup(subjectPublicKeyInfo, attributes, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        }
    public CertificateRequestInfo set(CertificateRequestInfo frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
