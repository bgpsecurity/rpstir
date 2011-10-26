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
package rules;
import name.*;
import asn.*;
public class KeyHash extends AsnInteger
    {
    public AsnObj snum = new AsnObj();
    public AsnObj sha1 = new AsnObj();
    public AsnObj trunc_sha1 = new AsnObj();
    public AsnObj uniq_val = new AsnObj();
    public KeyHash()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(snum, (int)1);
        _setup((AsnObj)null, snum, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sha1, (int)2);
        _setup(snum, sha1, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(trunc_sha1, (int)3);
        _setup(sha1, trunc_sha1, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(uniq_val, (int)4);
        _setup(trunc_sha1, uniq_val, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public KeyHash set(KeyHash frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
