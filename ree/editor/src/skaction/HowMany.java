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
public class HowMany extends AsnInteger
    {
    public AsnObj active = new AsnObj();
    public AsnObj all_keys = new AsnObj();
    public HowMany()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(active, (int)1);
        _setup((AsnObj)null, active, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(all_keys, (int)2);
        _setup(active, all_keys, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public HowMany set(HowMany frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
