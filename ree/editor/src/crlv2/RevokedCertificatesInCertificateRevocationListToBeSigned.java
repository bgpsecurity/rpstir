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
package crlv2;
import Algorithms.*;
import extensions.*;
// import serial_number.*;
import name.*;
import asn.*;
public class RevokedCertificatesInCertificateRevocationListToBeSigned extends AsnSequenceOf
    {
    public CRLEntry cRLEntry = new CRLEntry();
    public RevokedCertificatesInCertificateRevocationListToBeSigned()
        {
        _setup((AsnObj)null, cRLEntry, (short)0, (int)0x0);
        }
    public RevokedCertificatesInCertificateRevocationListToBeSigned set(RevokedCertificatesInCertificateRevocationListToBeSigned frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
