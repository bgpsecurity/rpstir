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
public class OwningASNumber extends AsnArray
    {
    public AsnInteger asnum = new AsnInteger();
    public AsnInteger rdi = new AsnInteger();
    public OwningASNumber()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, asnum, (short)0, (int)0x80);
        _setup(asnum, rdi, (short)0, (int)0x81);
        }
    public AsnObj _dup()
        {
        OwningASNumber objp = new OwningASNumber();
        _set_pointers(objp);
        return objp;
        }

    public OwningASNumber index(int index)
        {
        return (OwningASNumber)_index_op(index);
        }

    public OwningASNumber set(OwningASNumber frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
