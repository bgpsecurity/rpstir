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
public class DirectionInKeyMode extends AsnInteger
    {
    public AsnObj from_ciks = new AsnObj();
    public AsnObj to_ciks = new AsnObj();
    public DirectionInKeyMode()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(from_ciks, (int)1);
        _setup((AsnObj)null, from_ciks, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(to_ciks, (int)2);
        _setup(from_ciks, to_ciks, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public DirectionInKeyMode set(DirectionInKeyMode frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
