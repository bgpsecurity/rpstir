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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class PostalCodeInMerNames extends AsnChoice
    {
    public AsnVisibleString visibleString = new AsnVisibleString();
    public AsnBMPString bmpString = new AsnBMPString();
    public PostalCodeInMerNames()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, visibleString, (short)0, (int)0x0);
        visibleString._boundset(1, 14);
        _setup(visibleString, bmpString, (short)0, (int)0x0);
        bmpString._boundset(1, 14);
        }
    public PostalCodeInMerNames set(PostalCodeInMerNames frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
