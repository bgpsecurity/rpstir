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
public class PolicyQualifierInfo extends AsnArray
    {
    public PolicyQualifierInfoSetInPolicyQualifierInfo policyQualifierId = new PolicyQualifierInfoSetInPolicyQualifierInfo();
    public PolicyQualifierInfoSetDefined qualifier = new PolicyQualifierInfoSetDefined();
    public PolicyQualifierInfo()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, policyQualifierId, (short)0, (int)0x0);
        _setup(policyQualifierId, qualifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        PolicyQualifierInfo objp = new PolicyQualifierInfo();
        _set_pointers(objp);
        return objp;
        }

    public PolicyQualifierInfo index(int index)
        {
        return (PolicyQualifierInfo)_index_op(index);
        }

    public PolicyQualifierInfo set(PolicyQualifierInfo frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
