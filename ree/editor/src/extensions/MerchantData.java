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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class MerchantData extends AsnSequence
    {
    public MerchantID merID = new MerchantID();
    public AsnNumericString merAcquirerBIN = new AsnNumericString();
    public MerNameSeq merNameSeq = new MerNameSeq();
    public CountryCode merCountry = new CountryCode();
    public AsnBoolean merAuthFlag = new AsnBoolean();
    public MerchantData()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, merID, (short)0, (int)0x0);
        _setup(merID, merAcquirerBIN, (short)0, (int)0x0);
        merAcquirerBIN._boundset(6, 6);
        _setup(merAcquirerBIN, merNameSeq, (short)0, (int)0x0);
        _setup(merNameSeq, merCountry, (short)0, (int)0x0);
        _setup(merCountry, merAuthFlag, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        merAuthFlag._set_def(1);
        }
    public MerchantData set(MerchantData frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
