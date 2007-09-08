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
public class AdministrationDomainName extends AsnChoice
    {
    public AsnNumericString numeric = new AsnNumericString();
    public AsnPrintableString printable = new AsnPrintableString();
    public AdministrationDomainName()
        {
        _tag = 0x62;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, numeric, (short)0, (int)0x0);
        numeric._boundset(0, 16);
        _setup(numeric, printable, (short)0, (int)0x0);
        printable._boundset(0, 16);
        }
    public AdministrationDomainName set(AdministrationDomainName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
