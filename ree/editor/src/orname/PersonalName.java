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
package orname;
import name.*;
import asn.*;
public class PersonalName extends AsnSet
    {
    public AsnPrintableString surname = new AsnPrintableString();
    public AsnPrintableString given_name = new AsnPrintableString();
    public AsnPrintableString initials = new AsnPrintableString();
    public AsnPrintableString generational_qualifier = new AsnPrintableString();
    public PersonalName()
        {
        _setup((AsnObj)null, surname, (short)0, (int)0x80);
        surname._boundset(1, 40);
        _setup(surname, given_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        given_name._boundset(1, 16);
        _setup(given_name, initials, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        initials._boundset(1, 5);
        _setup(initials, generational_qualifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x83);
        generational_qualifier._boundset(1, 3);
        }
    public PersonalName set(PersonalName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
