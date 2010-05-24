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
package Algorithms;
import asn.*;
public class Kea_Dss_Parms extends AsnChoice
    {
    public Different_Parms diffParms = new Different_Parms();
    public Common_Parms commonParms = new Common_Parms();
    public Kea_Dss_Parms()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, diffParms, (short)(AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA0);
        _setup(diffParms, commonParms, (short)(AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA1);
        }
    public Kea_Dss_Parms set(Kea_Dss_Parms frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
