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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
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
public class SignReq extends AsnSequence
    {
    public AsnOctetString keyName = new AsnOctetString();
    public HashType hash = new HashType();
    public PadType pad = new PadType();
    public RuleType rules = new RuleType();
    public SignTypeInSignReq typ = new SignTypeInSignReq();
    public SignTypeDefined signd = new SignTypeDefined();
    public SignReq()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, hash, (short)0, (int)0x0);
        _setup(hash, pad, (short)0, (int)0x0);
        _setup(pad, rules, (short)0, (int)0x0);
        _setup(rules, typ, (short)0, (int)0x0);
        _setup(typ, signd, (short)0, (int)0x0);
        }
    public SignReq set(SignReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
