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
package crlv2;
import Algorithms.*;
import extensions.*;
// import serial_number.*;
import name.*;
import asn.*;
public class ChoiceOfTime extends AsnChoice
    {
    public AsnUTCTime utcTime = new AsnUTCTime();
    public AsnGeneralizedTime generalTime = new AsnGeneralizedTime();
    public ChoiceOfTime()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, utcTime, (short)0, (int)0x0);
        _setup(utcTime, generalTime, (short)0, (int)0x0);
        }
    public ChoiceOfTime set(ChoiceOfTime frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
