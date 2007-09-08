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
package Algorithms;
import asn.*;
public class Common_Parms extends AsnSequence
    {
    public AsnOctetString p = new AsnOctetString();
    public AsnOctetString q = new AsnOctetString();
    public AsnOctetString g = new AsnOctetString();
    public Common_Parms()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, p, (short)0, (int)0x0);
        _setup(p, q, (short)0, (int)0x0);
        _setup(q, g, (short)0, (int)0x0);
        }
    public Common_Parms set(Common_Parms frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
