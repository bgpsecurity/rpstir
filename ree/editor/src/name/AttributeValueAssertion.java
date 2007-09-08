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
package name;
import asn.*;
public class AttributeValueAssertion extends AsnArray
    {
    public SelectedAttributeTypesInAttributeValueAssertion objid = new SelectedAttributeTypesInAttributeValueAssertion();
    public SelectedAttributeTypesDefined value = new SelectedAttributeTypesDefined();
    public AttributeValueAssertion()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, objid, (short)0, (int)0x0);
        _setup(objid, value, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        AttributeValueAssertion objp = new AttributeValueAssertion();
        _set_pointers(objp);
        return objp;
        }

    public AttributeValueAssertion index(int index)
        {
        return (AttributeValueAssertion)_index_op(index);
        }

    public AttributeValueAssertion set(AttributeValueAssertion frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
