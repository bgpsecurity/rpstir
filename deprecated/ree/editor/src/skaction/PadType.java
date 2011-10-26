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
public class PadType extends AsnInteger
    {
    public AsnObj none = new AsnObj();
    public AsnObj pkcs1 = new AsnObj();
    public AsnObj x509 = new AsnObj();
    public AsnObj ffs = new AsnObj();
    public PadType()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(none, (int)0);
        _setup((AsnObj)null, none, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(pkcs1, (int)1);
        _setup(none, pkcs1, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(x509, (int)2);
        _setup(pkcs1, x509, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ffs, (int)3);
        _setup(x509, ffs, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public PadType set(PadType frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
