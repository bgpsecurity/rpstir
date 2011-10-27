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
public class Target extends AsnArray
    {
    public AsnInteger tagtype = new AsnInteger();
    public AsnInteger num = new AsnInteger();
    public AsnOctetString value = new AsnOctetString();
    public AsnObjectIdentifier objid = new AsnObjectIdentifier();
    public AsnBitString bits = new AsnBitString();
    public Range range = new Range();
    public _Targets and = new _Targets();
    public _Targets or = new _Targets();
    public _Targets not = new _Targets();
    public Target()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, tagtype, (short)0, (int)0x80);
        _setup(tagtype, num, (short)0, (int)0x0);
        _setup(num, value, (short)0, (int)0x0);
        _setup(value, objid, (short)0, (int)0x0);
        _setup(objid, bits, (short)0, (int)0x0);
        _setup(bits, range, (short)0, (int)0x0);
        _setup(range, and, (short)(AsnStatic.ASN_POINTER_FLAG), (int)0xA1);
        _setup(and, or, (short)(AsnStatic.ASN_POINTER_FLAG), (int)0xA2);
        _setup(or, not, (short)(AsnStatic.ASN_POINTER_FLAG), (int)0xA3);
        }
    public AsnObj _dup()
        {
        Target objp = new Target();
        _set_pointers(objp);
        return objp;
        }

    public Target index(int index)
        {
        return (Target)_index_op(index);
        }

    public Target set(Target frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
