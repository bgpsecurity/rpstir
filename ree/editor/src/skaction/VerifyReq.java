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
public class VerifyReq extends AsnSequence
    {
    public HashType hash = new HashType();
    public PadType pad = new PadType();
    public VerifyTypeInVerifyReq typ = new VerifyTypeInVerifyReq();
    public VerifyTypeDefined signd = new VerifyTypeDefined();
    public KeyNameOrPubKey keyOrName = new KeyNameOrPubKey();
    public VerifyReq()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, hash, (short)0, (int)0x0);
        _setup(hash, pad, (short)0, (int)0x0);
        _setup(pad, typ, (short)0, (int)0x0);
        _setup(typ, signd, (short)0, (int)0x0);
        _setup(signd, keyOrName, (short)0, (int)0x0);
        }
    public VerifyReq set(VerifyReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
