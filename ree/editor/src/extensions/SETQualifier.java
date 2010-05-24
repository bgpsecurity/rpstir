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
public class SETQualifier extends AsnSequence
    {
    public TerseStatementInSETQualifier terseStatement = new TerseStatementInSETQualifier();
    public AsnVisibleString policyURL = new AsnVisibleString();
    public AsnVisibleString policyEmail = new AsnVisibleString();
    public SETQualifier()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, terseStatement, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(terseStatement, policyURL, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        policyURL._boundset(1, 512);
        _setup(policyURL, policyEmail, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        policyEmail._boundset(1, 512);
        }
    public SETQualifier set(SETQualifier frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
