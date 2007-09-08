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
public class KeyConfig extends AsnArray
    {
    public AsnOctetString keyName = new AsnOctetString();
    public KeyUses keyUses = new KeyUses();
    public AsnInteger threshold = new AsnInteger();
    public AsnInteger sharecount = new AsnInteger();
    public AsnGeneralizedTime not_before = new AsnGeneralizedTime();
    public AsnGeneralizedTime not_after = new AsnGeneralizedTime();
    public KeyStatus status = new KeyStatus();
    public KeyConfig()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, keyUses, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(keyUses, threshold, (short)0, (int)0x0);
        _setup(threshold, sharecount, (short)0, (int)0x0);
        _setup(sharecount, not_before, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(not_before, not_after, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(not_after, status, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        KeyConfig objp = new KeyConfig();
        _set_pointers(objp);
        return objp;
        }

    public KeyConfig index(int index)
        {
        return (KeyConfig)_index_op(index);
        }

    public KeyConfig set(KeyConfig frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
