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
public class InitResp extends AsnSequence
    {
    public Name name = new Name();
    public SubjectPublicKeyInfo pub_key = new SubjectPublicKeyInfo();
    public AsnOctetString des_key = new AsnOctetString();
    public InitResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, pub_key, (short)0, (int)0x0);
        _setup(pub_key, des_key, (short)0, (int)0x0);
        }
    public InitResp set(InitResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
