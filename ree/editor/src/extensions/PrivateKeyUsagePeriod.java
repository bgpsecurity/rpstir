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
public class PrivateKeyUsagePeriod extends AsnArray
    {
    public AsnGeneralizedTime notBefore = new AsnGeneralizedTime();
    public AsnGeneralizedTime notAfter = new AsnGeneralizedTime();
    public PrivateKeyUsagePeriod()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, notBefore, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(notBefore, notAfter, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        }
    public AsnObj _dup()
        {
        PrivateKeyUsagePeriod objp = new PrivateKeyUsagePeriod();
        _set_pointers(objp);
        return objp;
        }

    public PrivateKeyUsagePeriod index(int index)
        {
        return (PrivateKeyUsagePeriod)_index_op(index);
        }

    public PrivateKeyUsagePeriod set(PrivateKeyUsagePeriod frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
