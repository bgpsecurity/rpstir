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
public class NetkeyToBeSigned extends AsnSequence
    {
    public SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    public AsnIA5String challenge = new AsnIA5String();
    public NetkeyToBeSigned()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, subjectPublicKeyInfo, (short)0, (int)0x0);
        _setup(subjectPublicKeyInfo, challenge, (short)0, (int)0x0);
        }
    public NetkeyToBeSigned set(NetkeyToBeSigned frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
