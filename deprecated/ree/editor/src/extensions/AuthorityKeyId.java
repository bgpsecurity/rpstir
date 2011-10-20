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
public class AuthorityKeyId extends AsnArray
    {
    public AsnOctetString keyIdentifier = new AsnOctetString();
    public GeneralNames certIssuer = new GeneralNames();
    public AsnInteger certSerialNumber = new AsnInteger();
    public AuthorityKeyId()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, keyIdentifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(keyIdentifier, certIssuer, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA1);
        _setup(certIssuer, certSerialNumber, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        }
    public AsnObj _dup()
        {
        AuthorityKeyId objp = new AuthorityKeyId();
        _set_pointers(objp);
        return objp;
        }

    public AuthorityKeyId index(int index)
        {
        return (AuthorityKeyId)_index_op(index);
        }

    public AuthorityKeyId set(AuthorityKeyId frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
