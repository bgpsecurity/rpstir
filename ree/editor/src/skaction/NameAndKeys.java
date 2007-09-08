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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class NameAndKeys extends AsnArray
    {
    public Name name = new Name();
    public KeyNames keyNames = new KeyNames();
    public NameAndKeys()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, keyNames, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        NameAndKeys objp = new NameAndKeys();
        _set_pointers(objp);
        return objp;
        }

    public NameAndKeys index(int index)
        {
        return (NameAndKeys)_index_op(index);
        }

    public NameAndKeys set(NameAndKeys frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
