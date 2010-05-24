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
public class Attribute extends AsnArray
    {
    public AttributeTableInAttribute type = new AttributeTableInAttribute();
    public ValuesInAttribute values = new ValuesInAttribute();
    public Attribute()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type, (short)0, (int)0x0);
        _setup(type, values, (short)0, (int)0x0);
        values._boundset(1, 20);
        }
    public AsnObj _dup()
        {
        Attribute objp = new Attribute();
        _set_pointers(objp);
        return objp;
        }

    public Attribute index(int index)
        {
        return (Attribute)_index_op(index);
        }

    public Attribute set(Attribute frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
