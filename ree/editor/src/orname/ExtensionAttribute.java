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
package orname;
import name.*;
import asn.*;
public class ExtensionAttribute extends AsnArray
    {
    public AsnInteger extension_attribute_type = new AsnInteger();
    public ExtensionAttribute()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, extension_attribute_type, (short)0, (int)0x80);
        }
    public AsnObj _dup()
        {
        ExtensionAttribute objp = new ExtensionAttribute();
        _set_pointers(objp);
        return objp;
        }

    public ExtensionAttribute index(int index)
        {
        return (ExtensionAttribute)_index_op(index);
        }

    public ExtensionAttribute set(ExtensionAttribute frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
