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
package rules;
import name.*;
import asn.*;
public class IdAndLimit extends AsnArray
    {
    public ObjidOrInt id = new ObjidOrInt();
    public AsnInteger max = new AsnInteger();
    public AsnInteger min = new AsnInteger();
    public IdAndLimit()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, id, (short)0, (int)0x0);
        _setup(id, max, (short)0, (int)0x0);
        _setup(max, min, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        min._set_def(0);
        }
    public AsnObj _dup()
        {
        IdAndLimit objp = new IdAndLimit();
        _set_pointers(objp);
        return objp;
        }

    public IdAndLimit index(int index)
        {
        return (IdAndLimit)_index_op(index);
        }

    public IdAndLimit set(IdAndLimit frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
