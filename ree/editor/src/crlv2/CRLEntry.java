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
public class CRLEntry extends AsnArray
    {
    public AsnInteger userCertificate = new AsnInteger();
    public ChoiceOfTime revocationDate = new ChoiceOfTime();
    public CrlEntryExtensions extensions = new CrlEntryExtensions();
    public CRLEntry()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, userCertificate, (short)0, (int)0x0);
        _setup(userCertificate, revocationDate, (short)0, (int)0x0);
        _setup(revocationDate, extensions, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        CRLEntry objp = new CRLEntry();
        _set_pointers(objp);
        return objp;
        }

    public CRLEntry index(int index)
        {
        return (CRLEntry)_index_op(index);
        }

    public CRLEntry set(CRLEntry frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
