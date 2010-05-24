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
package certificate;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import extensions.*;
import asn.*;
public class ForwardCertificationPath extends AsnArrayOfSequencesOf
    {
    public CrossCertificates crossCertificates = new CrossCertificates();
    public ForwardCertificationPath()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, crossCertificates, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        ForwardCertificationPath objp = new ForwardCertificationPath();
        _set_pointers(objp);
        return objp;
        }

    public ForwardCertificationPath index(int index)
        {
        return (ForwardCertificationPath)_index_op(index);
        }

    public ForwardCertificationPath set(ForwardCertificationPath frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
