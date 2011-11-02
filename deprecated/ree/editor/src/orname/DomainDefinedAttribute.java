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
package orname;
import name.*;
import asn.*;
public class DomainDefinedAttribute extends AsnArray
    {
    public AsnPrintableString type = new AsnPrintableString();
    public AsnPrintableString value = new AsnPrintableString();
    public DomainDefinedAttribute()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type, (short)0, (int)0x0);
        type._boundset(1, 8);
        _setup(type, value, (short)0, (int)0x0);
        value._boundset(1, 128);
        }
    public AsnObj _dup()
        {
        DomainDefinedAttribute objp = new DomainDefinedAttribute();
        _set_pointers(objp);
        return objp;
        }

    public DomainDefinedAttribute index(int index)
        {
        return (DomainDefinedAttribute)_index_op(index);
        }

    public DomainDefinedAttribute set(DomainDefinedAttribute frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
