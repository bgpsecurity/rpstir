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
public class InitReq extends AsnSequence
    {
    public AsnInteger id = new AsnInteger();
    public AsnGeneralizedTime date_time = new AsnGeneralizedTime();
    public Name name = new Name();
    public AlgTypeTableInInitReq alg = new AlgTypeTableInInitReq();
    public AlgTypeTableDefined params = new AlgTypeTableDefined();
    public DESKey des_key = new DESKey();
    public InitReq()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, id, (short)0, (int)0x0);
        _setup(id, date_time, (short)0, (int)0x0);
        _setup(date_time, name, (short)0, (int)0x0);
        _setup(name, alg, (short)0, (int)0x0);
        _setup(alg, params, (short)0, (int)0x0);
        _setup(params, des_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public InitReq set(InitReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
