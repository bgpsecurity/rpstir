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
public class ObjidOrInt extends AsnChoice
    {
    public AsnObjectIdentifier objid = new AsnObjectIdentifier();
    public AsnInteger num = new AsnInteger();
    public AsnInteger tag = new AsnInteger();
    public ObjidOrInt()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, objid, (short)0, (int)0x0);
        _setup(objid, num, (short)0, (int)0x0);
        _setup(num, tag, (short)0, (int)0x80);
        }
    public ObjidOrInt set(ObjidOrInt frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
