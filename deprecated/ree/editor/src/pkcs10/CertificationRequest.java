/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class CertificationRequest extends AsnArray
    {
    public CertificateRequestInfo toBeSigned = new CertificateRequestInfo();
    public AlgorithmIdentifier algorithm = new AlgorithmIdentifier();
    public AsnBitString signature = new AsnBitString();
    public CertificationRequest()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, toBeSigned, (short)0, (int)0x0);
        _setup(toBeSigned, algorithm, (short)0, (int)0x0);
        _setup(algorithm, signature, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        CertificationRequest objp = new CertificationRequest();
        _set_pointers(objp);
        return objp;
        }

    public CertificationRequest index(int index)
        {
        return (CertificationRequest)_index_op(index);
        }

    public CertificationRequest set(CertificationRequest frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
