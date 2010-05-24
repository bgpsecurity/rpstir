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
public class RangeLimit extends AsnChoice
    {
    public AsnInteger number = new AsnInteger();
    public AsnBitString bits = new AsnBitString();
    public AsnOctetString left = new AsnOctetString();
    public AsnOctetString right = new AsnOctetString();
    public AsnInteger param = new AsnInteger();
    public RangeLimit()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, number, (short)0, (int)0x0);
        _setup(number, bits, (short)0, (int)0x0);
        _setup(bits, left, (short)0, (int)0x0);
        _setup(left, right, (short)0, (int)0x80);
        _setup(right, param, (short)0, (int)0x81);
        }
    public RangeLimit set(RangeLimit frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
