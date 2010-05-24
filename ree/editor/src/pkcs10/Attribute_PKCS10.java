/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class Attribute_PKCS10 extends AsnArray
    {
    public TableInAttribute_PKCS10 type = new TableInAttribute_PKCS10();
    public TableDefined value = new TableDefined();
    public Attribute_PKCS10()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type, (short)0, (int)0x0);
        _setup(type, value, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        Attribute_PKCS10 objp = new Attribute_PKCS10();
        _set_pointers(objp);
        return objp;
        }

    public Attribute_PKCS10 index(int index)
        {
        return (Attribute_PKCS10)_index_op(index);
        }

    public Attribute_PKCS10 set(Attribute_PKCS10 frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
