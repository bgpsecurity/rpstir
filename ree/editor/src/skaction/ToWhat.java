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
public class ToWhat extends AsnInteger
    {
    public AsnObj keep = new AsnObj();
    public AsnObj fresh = new AsnObj();
    public AsnObj to_exist = new AsnObj();
    public ToWhat()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(keep, (int)1);
        _setup((AsnObj)null, keep, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(fresh, (int)2);
        _setup(keep, fresh, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(to_exist, (int)3);
        _setup(fresh, to_exist, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public ToWhat set(ToWhat frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
