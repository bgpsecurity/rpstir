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
public class DiffieHellmanParameters extends AsnSequence
    {
    public AsnInteger prime = new AsnInteger();
    public AsnInteger base = new AsnInteger();
    public AsnInteger privateValueLength = new AsnInteger();
    public DiffieHellmanParameters()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, prime, (short)0, (int)0x0);
        _setup(prime, base, (short)0, (int)0x0);
        _setup(base, privateValueLength, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public DiffieHellmanParameters set(DiffieHellmanParameters frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
