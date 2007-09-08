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
public class KeyOpsOpcode extends AsnInteger
    {
    public AsnObj rename = new AsnObj();
    public AsnObj duplicate = new AsnObj();
    public KeyOpsOpcode()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(rename, (int)1);
        _setup((AsnObj)null, rename, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(duplicate, (int)2);
        _setup(rename, duplicate, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public KeyOpsOpcode set(KeyOpsOpcode frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
