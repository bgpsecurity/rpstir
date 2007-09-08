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
public class ASNumberOrRange extends AsnArray
    {
    public AsnInteger num = new AsnInteger();
    public ASRange range = new ASRange();
    public ASNumberOrRange()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, num, (short)0, (int)0x0);
        _setup(num, range, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        ASNumberOrRange objp = new ASNumberOrRange();
        _set_pointers(objp);
        return objp;
        }

    public ASNumberOrRange index(int index)
        {
        return (ASNumberOrRange)_index_op(index);
        }

    public ASNumberOrRange set(ASNumberOrRange frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
