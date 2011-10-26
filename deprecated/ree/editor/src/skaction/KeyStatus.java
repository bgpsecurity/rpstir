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
public class KeyStatus extends AsnInteger
    {
    public AsnObj none = new AsnObj();
    public AsnObj cik = new AsnObj();
    public AsnObj active = new AsnObj();
    public KeyStatus()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(none, (int)0);
        _setup((AsnObj)null, none, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cik, (int)1);
        _setup(none, cik, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(active, (int)2);
        _setup(cik, active, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public KeyStatus set(KeyStatus frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
