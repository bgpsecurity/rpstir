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
public class KeyUsage extends AsnArray
    {
    public AsnBit digitalSignature = new AsnBit();
    public AsnBit nonRepudiation = new AsnBit();
    public AsnBit keyEncipherment = new AsnBit();
    public AsnBit dataEncipherment = new AsnBit();
    public AsnBit keyAgreement = new AsnBit();
    public AsnBit keyCertSign = new AsnBit();
    public AsnBit cRLSign = new AsnBit();
    public AsnBit encipherOnly = new AsnBit();
    public AsnBit decipherOnly = new AsnBit();
    public KeyUsage()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(digitalSignature, (int)0);
        _setup((AsnObj)null, digitalSignature, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(nonRepudiation, (int)1);
        _setup(digitalSignature, nonRepudiation, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(keyEncipherment, (int)2);
        _setup(nonRepudiation, keyEncipherment, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(dataEncipherment, (int)3);
        _setup(keyEncipherment, dataEncipherment, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(keyAgreement, (int)4);
        _setup(dataEncipherment, keyAgreement, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(keyCertSign, (int)5);
        _setup(keyAgreement, keyCertSign, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cRLSign, (int)6);
        _setup(keyCertSign, cRLSign, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(encipherOnly, (int)7);
        _setup(cRLSign, encipherOnly, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(decipherOnly, (int)8);
        _setup(encipherOnly, decipherOnly, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        KeyUsage objp = new KeyUsage();
        _set_pointers(objp);
        return objp;
        }

    public KeyUsage index(int index)
        {
        return (KeyUsage)_index_op(index);
        }

    public KeyUsage set(KeyUsage frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
