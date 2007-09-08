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
package certificate;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import extensions.*;
import asn.*;
public class CrossCertificates extends AsnArrayOfSetsOf
    {
    public Certificate certificate = new Certificate();
    public CrossCertificates()
        {
        _setup((AsnObj)null, certificate, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        CrossCertificates objp = new CrossCertificates();
        _set_pointers(objp);
        return objp;
        }

    public CrossCertificates index(int index)
        {
        return (CrossCertificates)_index_op(index);
        }

    public CrossCertificates set(CrossCertificates frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
