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
public class ActivateKeyResp extends AsnSequence
    {
    public Name name = new Name();
    public AsnInteger low = new AsnInteger();
    public AsnInteger high = new AsnInteger();
    public AsnInteger next = new AsnInteger();
    public ActivatedKeys keyNames = new ActivatedKeys();
    public ActivateKeyResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, low, (short)0, (int)0x0);
        _setup(low, high, (short)0, (int)0x0);
        _setup(high, next, (short)0, (int)0x0);
        _setup(next, keyNames, (short)0, (int)0x0);
        }
    public ActivateKeyResp set(ActivateKeyResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
