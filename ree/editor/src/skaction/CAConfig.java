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
public class CAConfig extends AsnArray
    {
    public Name name = new Name();
    public AsnInteger lo_snum = new AsnInteger();
    public AsnInteger hi_snum = new AsnInteger();
    public AsnInteger last_snum = new AsnInteger();
    public AsnInteger last_crl = new AsnInteger();
    public AsnInteger ctr1 = new AsnInteger();
    public AsnInteger ctr2 = new AsnInteger();
    public AsnInteger ctr3 = new AsnInteger();
    public KeyConfigs key_configs = new KeyConfigs();
    public CAConfig()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, lo_snum, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(lo_snum, hi_snum, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(hi_snum, last_snum, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        _setup(last_snum, last_crl, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x83);
        _setup(last_crl, ctr1, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x84);
        _setup(ctr1, ctr2, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x85);
        _setup(ctr2, ctr3, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x86);
        _setup(ctr3, key_configs, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA8);
        }
    public AsnObj _dup()
        {
        CAConfig objp = new CAConfig();
        _set_pointers(objp);
        return objp;
        }

    public CAConfig index(int index)
        {
        return (CAConfig)_index_op(index);
        }

    public CAConfig set(CAConfig frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
