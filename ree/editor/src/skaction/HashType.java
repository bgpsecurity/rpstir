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
public class HashType extends AsnInteger
    {
    public AsnObj none = new AsnObj();
    public AsnObj sha1 = new AsnObj();
    public AsnObj md2 = new AsnObj();
    public AsnObj md5 = new AsnObj();
    public HashType()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(none, (int)0);
        _setup((AsnObj)null, none, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sha1, (int)1);
        _setup(none, sha1, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(md2, (int)2);
        _setup(sha1, md2, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(md5, (int)5);
        _setup(md2, md5, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public HashType set(HashType frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
