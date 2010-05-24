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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class ASIdentifierChoice extends AsnChoice
    {
    public AsnBoolean inherit = new AsnBoolean();
    public AsNumbersOrRangesInASIdentifierChoice asNumbersOrRanges = new AsNumbersOrRangesInASIdentifierChoice();
    public ASIdentifierChoice()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, inherit, (short)0, (int)0x0);
        _setup(inherit, asNumbersOrRanges, (short)0, (int)0x0);
        }
    public ASIdentifierChoice set(ASIdentifierChoice frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
