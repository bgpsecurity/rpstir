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
public class GeneralSubtree extends AsnArray
    {
    public GeneralName base = new GeneralName();
    public AsnInteger minimum = new AsnInteger();
    public AsnInteger maximum = new AsnInteger();
    public GeneralSubtree()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, base, (short)0, (int)0x0);
        _setup(base, minimum, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x80);
        minimum._set_def(0);
        _setup(minimum, maximum, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        }
    public AsnObj _dup()
        {
        GeneralSubtree objp = new GeneralSubtree();
        _set_pointers(objp);
        return objp;
        }

    public GeneralSubtree index(int index)
        {
        return (GeneralSubtree)_index_op(index);
        }

    public GeneralSubtree set(GeneralSubtree frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
