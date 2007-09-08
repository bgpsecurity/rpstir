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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class PolicyMappings extends AsnArrayOfSequencesOf
    {
    public SequenceInPolicyMappings sequenceInPolicyMappings = new SequenceInPolicyMappings();
    public PolicyMappings()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, sequenceInPolicyMappings, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        PolicyMappings objp = new PolicyMappings();
        _set_pointers(objp);
        return objp;
        }

    public PolicyMappings index(int index)
        {
        return (PolicyMappings)_index_op(index);
        }

    public PolicyMappings set(PolicyMappings frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
