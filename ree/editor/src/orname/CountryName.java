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
package orname;
import name.*;
import asn.*;
public class CountryName extends AsnChoice
    {
    public AsnNumericString x121_dcc_code = new AsnNumericString();
    public AsnPrintableString iso_3166_alpha2_code = new AsnPrintableString();
    public CountryName()
        {
        _tag = 0x61;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, x121_dcc_code, (short)0, (int)0x0);
        x121_dcc_code._boundset(3, 3);
        _setup(x121_dcc_code, iso_3166_alpha2_code, (short)0, (int)0x0);
        iso_3166_alpha2_code._boundset(2, 2);
        }
    public CountryName set(CountryName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
