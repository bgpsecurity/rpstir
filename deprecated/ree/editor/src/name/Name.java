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
package name;
import asn.*;
public class Name extends AsnArray
    {
    public RDNSequence rDNSequence = new RDNSequence();
    public Name()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, rDNSequence, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        Name objp = new Name();
        _set_pointers(objp);
        return objp;
        }

    public Name index(int index)
        {
        return (Name)_index_op(index);
        }

    public Name set(Name frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
