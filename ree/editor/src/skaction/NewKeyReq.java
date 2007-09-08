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
public class NewKeyReq extends AsnSequence
    {
    public Name ca_name = new Name();
    public AsnOctetString keyName = new AsnOctetString();
    public KeyUses keyUses = new KeyUses();
    public AsnInteger reuse = new AsnInteger();
    public AlgTypeTableInNewKeyReq alg = new AlgTypeTableInNewKeyReq();
    public AlgTypeTableDefined params = new AlgTypeTableDefined();
    public CIKs ciks = new CIKs();
    public NewKeyRespFormats formats = new NewKeyRespFormats();
    public NewKeyReq()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, ca_name, (short)0, (int)0x0);
        _setup(ca_name, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, keyUses, (short)0, (int)0x0);
        _setup(keyUses, reuse, (short)0, (int)0x0);
        _setup(reuse, alg, (short)0, (int)0x0);
        _setup(alg, params, (short)0, (int)0x0);
        _setup(params, ciks, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(ciks, formats, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public NewKeyReq set(NewKeyReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
