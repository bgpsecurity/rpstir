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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class RouterIdentifier extends AsnArrayOfSequencesOf
    {
    public OwningASNumber owningASNumber = new OwningASNumber();
    public RouterIdentifier()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, owningASNumber, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        RouterIdentifier objp = new RouterIdentifier();
        _set_pointers(objp);
        return objp;
        }

    public RouterIdentifier index(int index)
        {
        return (RouterIdentifier)_index_op(index);
        }

    public RouterIdentifier set(RouterIdentifier frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
