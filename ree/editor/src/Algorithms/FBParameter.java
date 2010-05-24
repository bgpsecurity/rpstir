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
public class FBParameter extends AsnSequence
    {
    public AsnOctetString iv = new AsnOctetString();
    public AsnInteger numberOfBits = new AsnInteger();
    public FBParameter()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, iv, (short)0, (int)0x0);
        _setup(iv, numberOfBits, (short)0, (int)0x0);
        }
    public FBParameter set(FBParameter frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
