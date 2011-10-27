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
public class ReasonFlags extends AsnArray
    {
    public AsnBit unused = new AsnBit();
    public AsnBit keyCompromise = new AsnBit();
    public AsnBit caCompromise = new AsnBit();
    public AsnBit affiliationChanged = new AsnBit();
    public AsnBit superseded = new AsnBit();
    public AsnBit cessationOfOperation = new AsnBit();
    public AsnBit certificateHold = new AsnBit();
    public ReasonFlags()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(unused, (int)0);
        _setup((AsnObj)null, unused, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(keyCompromise, (int)1);
        _setup(unused, keyCompromise, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(caCompromise, (int)2);
        _setup(keyCompromise, caCompromise, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(affiliationChanged, (int)3);
        _setup(caCompromise, affiliationChanged, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(superseded, (int)4);
        _setup(affiliationChanged, superseded, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cessationOfOperation, (int)5);
        _setup(superseded, cessationOfOperation, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(certificateHold, (int)6);
        _setup(cessationOfOperation, certificateHold, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        ReasonFlags objp = new ReasonFlags();
        _set_pointers(objp);
        return objp;
        }

    public ReasonFlags index(int index)
        {
        return (ReasonFlags)_index_op(index);
        }

    public ReasonFlags set(ReasonFlags frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
