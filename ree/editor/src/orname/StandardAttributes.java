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
public class StandardAttributes extends AsnSequence
    {
    public CountryName country_name = new CountryName();
    public AdministrationDomainName administration_domain_name = new AdministrationDomainName();
    public AsnNumericString network_address = new AsnNumericString();
    public AsnPrintableString terminal_identifier = new AsnPrintableString();
    public PrivateDomainName private_domain_name = new PrivateDomainName();
    public AsnPrintableString organization_name = new AsnPrintableString();
    public AsnNumericString numeric_user_identifier = new AsnNumericString();
    public PersonalName personal_name = new PersonalName();
    public OrganizationalUnitNames organizational_unit_names = new OrganizationalUnitNames();
    public StandardAttributes()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, country_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x61);
        _setup(country_name, administration_domain_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x62);
        _setup(administration_domain_name, network_address, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        network_address._boundset(1, 15);
        _setup(network_address, terminal_identifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        terminal_identifier._boundset(1, 24);
        _setup(terminal_identifier, private_domain_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA2);
        _setup(private_domain_name, organization_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x83);
        organization_name._boundset(1, 64);
        _setup(organization_name, numeric_user_identifier, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x84);
        numeric_user_identifier._boundset(1, 32);
        _setup(numeric_user_identifier, personal_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA5);
        _setup(personal_name, organizational_unit_names, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA6);
        }
    public StandardAttributes set(StandardAttributes frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
