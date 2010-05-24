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
public class Certificates extends AsnArray
    {
    public Certificate certificate = new Certificate();
    public ForwardCertificationPath certificationPath = new ForwardCertificationPath();
    public Certificates()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, certificate, (short)0, (int)0x0);
        _setup(certificate, certificationPath, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        Certificates objp = new Certificates();
        _set_pointers(objp);
        return objp;
        }

    public Certificates index(int index)
        {
        return (Certificates)_index_op(index);
        }

    public Certificates set(Certificates frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
