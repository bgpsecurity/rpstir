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
public class IPAddressFamily extends AsnArray
    {
    public AsnOctetString addressFamily = new AsnOctetString();
    public IPAddressChoice ipAddressChoice = new IPAddressChoice();
    public IPAddressFamily()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, addressFamily, (short)0, (int)0x0);
        addressFamily._boundset(2, 3);
        _setup(addressFamily, ipAddressChoice, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        IPAddressFamily objp = new IPAddressFamily();
        _set_pointers(objp);
        return objp;
        }

    public IPAddressFamily index(int index)
        {
        return (IPAddressFamily)_index_op(index);
        }

    public IPAddressFamily set(IPAddressFamily frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
