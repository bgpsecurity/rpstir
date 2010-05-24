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
public class RDNSequence extends AsnArrayOfSequencesOf
    {
    public RelativeDistinguishedName relativeDistinguishedName = new RelativeDistinguishedName();
    public RDNSequence()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, relativeDistinguishedName, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        RDNSequence objp = new RDNSequence();
        _set_pointers(objp);
        return objp;
        }

    public RDNSequence index(int index)
        {
        return (RDNSequence)_index_op(index);
        }

    public RDNSequence set(RDNSequence frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
