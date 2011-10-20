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
public class CertificateValidityDate extends AsnArray
    {
    public AsnUTCTime utcTime = new AsnUTCTime();
    public AsnGeneralizedTime generalTime = new AsnGeneralizedTime();
    public CertificateValidityDate()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, utcTime, (short)0, (int)0x0);
        _setup(utcTime, generalTime, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        CertificateValidityDate objp = new CertificateValidityDate();
        _set_pointers(objp);
        return objp;
        }

    public CertificateValidityDate index(int index)
        {
        return (CertificateValidityDate)_index_op(index);
        }

    public CertificateValidityDate set(CertificateValidityDate frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
