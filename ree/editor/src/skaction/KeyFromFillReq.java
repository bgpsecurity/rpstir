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
public class KeyFromFillReq extends AsnSequence
    {
    public Name to_ca = new Name();
    public AsnOctetString to_keyName = new AsnOctetString();
    public Name from_ca = new Name();
    public AsnOctetString from_keyName = new AsnOctetString();
    public AsnInteger alg = new AsnInteger();
    public KeyFromFillReq()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, to_ca, (short)0, (int)0x0);
        _setup(to_ca, to_keyName, (short)0, (int)0x0);
        to_keyName._boundset(1, 16);
        _setup(to_keyName, from_ca, (short)0, (int)0x0);
        _setup(from_ca, from_keyName, (short)0, (int)0x0);
        from_keyName._boundset(1, 16);
        _setup(from_keyName, alg, (short)0, (int)0x0);
        }
    public KeyFromFillReq set(KeyFromFillReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
