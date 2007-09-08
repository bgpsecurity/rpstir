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
public class PrivateDomainName extends AsnChoice
    {
    public AsnNumericString numeric = new AsnNumericString();
    public AsnPrintableString printable = new AsnPrintableString();
    public PrivateDomainName()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, numeric, (short)0, (int)0x0);
        numeric._boundset(1, 16);
        _setup(numeric, printable, (short)0, (int)0x0);
        printable._boundset(1, 16);
        }
    public PrivateDomainName set(PrivateDomainName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
