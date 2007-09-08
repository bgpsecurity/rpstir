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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class SignedDeliverable extends AsnSequence
    {
    public AsnBitString sig = new AsnBitString();
    public HashInSignedDeliverable hash = new HashInSignedDeliverable();
    public Certificate ctf = new Certificate();
    public SignedDeliverable()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, sig, (short)0, (int)0x0);
        _setup(sig, hash, (short)0, (int)0x0);
        _setup(hash, ctf, (short)0, (int)0x0);
        }
    public SignedDeliverable set(SignedDeliverable frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
