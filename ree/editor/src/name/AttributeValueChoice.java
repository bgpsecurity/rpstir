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
public class AttributeValueChoice extends AsnSequence
    {
    public AsnObjectIdentifier objid = new AsnObjectIdentifier();
    public DirectoryString value = new DirectoryString();
    public AttributeValueChoice()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, objid, (short)0, (int)0x0);
        _setup(objid, value, (short)0, (int)0x0);
        }
    public AttributeValueChoice set(AttributeValueChoice frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
