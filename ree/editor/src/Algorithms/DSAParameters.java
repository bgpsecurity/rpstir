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
package Algorithms;
import asn.*;
public class DSAParameters extends AsnArray
    {
    public AsnInteger prime1 = new AsnInteger();
    public AsnInteger prime2 = new AsnInteger();
    public AsnInteger base = new AsnInteger();
    public DSAParameters()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, prime1, (short)0, (int)0x0);
        _setup(prime1, prime2, (short)0, (int)0x0);
        _setup(prime2, base, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        DSAParameters objp = new DSAParameters();
        _set_pointers(objp);
        return objp;
        }

    public DSAParameters index(int index)
        {
        return (DSAParameters)_index_op(index);
        }

    public DSAParameters set(DSAParameters frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
