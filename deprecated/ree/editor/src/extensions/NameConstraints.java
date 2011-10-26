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
public class NameConstraints extends AsnArray
    {
    public GeneralSubtrees permittedSubtrees = new GeneralSubtrees();
    public GeneralSubtrees excludedSubtrees = new GeneralSubtrees();
    public NameConstraints()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, permittedSubtrees, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(permittedSubtrees, excludedSubtrees, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA1);
        }
    public AsnObj _dup()
        {
        NameConstraints objp = new NameConstraints();
        _set_pointers(objp);
        return objp;
        }

    public NameConstraints index(int index)
        {
        return (NameConstraints)_index_op(index);
        }

    public NameConstraints set(NameConstraints frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
