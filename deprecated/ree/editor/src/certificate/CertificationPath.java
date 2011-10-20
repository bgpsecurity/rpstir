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
public class CertificationPath extends AsnArray
    {
    public Certificate userCertificate = new Certificate();
    public TheCACertificatesInCertificationPath theCACertificates = new TheCACertificatesInCertificationPath();
    public CertificationPath()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, userCertificate, (short)0, (int)0x0);
        _setup(userCertificate, theCACertificates, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        CertificationPath objp = new CertificationPath();
        _set_pointers(objp);
        return objp;
        }

    public CertificationPath index(int index)
        {
        return (CertificationPath)_index_op(index);
        }

    public CertificationPath set(CertificationPath frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
