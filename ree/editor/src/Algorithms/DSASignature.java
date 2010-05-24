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
package Algorithms;
import asn.*;
public class DSASignature extends AsnArray
    {
    public AsnInteger arr = new AsnInteger();
    public AsnInteger ess = new AsnInteger();
    public DSASignature()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, arr, (short)0, (int)0x0);
        _setup(arr, ess, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        DSASignature objp = new DSASignature();
        _set_pointers(objp);
        return objp;
        }

    public DSASignature index(int index)
        {
        return (DSASignature)_index_op(index);
        }

    public DSASignature set(DSASignature frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
