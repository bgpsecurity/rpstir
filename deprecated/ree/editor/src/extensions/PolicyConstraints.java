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
public class PolicyConstraints extends AsnArray
    {
    public AsnInteger requireExplicitPolicy = new AsnInteger();
    public AsnInteger inhibitPolicyMapping = new AsnInteger();
    public PolicyConstraints()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, requireExplicitPolicy, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(requireExplicitPolicy, inhibitPolicyMapping, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        }
    public AsnObj _dup()
        {
        PolicyConstraints objp = new PolicyConstraints();
        _set_pointers(objp);
        return objp;
        }

    public PolicyConstraints index(int index)
        {
        return (PolicyConstraints)_index_op(index);
        }

    public PolicyConstraints set(PolicyConstraints frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
