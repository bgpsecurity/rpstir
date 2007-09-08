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
public class AdditionalPolicy extends AsnArray
    {
    public AsnObjectIdentifier policyOID = new AsnObjectIdentifier();
    public SETQualifier policyQualifier = new SETQualifier();
    public CertificateType policyAddedBy = new CertificateType();
    public AdditionalPolicy()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, policyOID, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(policyOID, policyQualifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(policyQualifier, policyAddedBy, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        AdditionalPolicy objp = new AdditionalPolicy();
        _set_pointers(objp);
        return objp;
        }

    public AdditionalPolicy index(int index)
        {
        return (AdditionalPolicy)_index_op(index);
        }

    public AdditionalPolicy set(AdditionalPolicy frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
