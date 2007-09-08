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
package name;
import asn.*;
public class SelectedAttributeTypesDefined extends AsnChoice
    {
    public DirectoryString commonName = new DirectoryString();
    public DirectoryString surname = new DirectoryString();
    public AsnPrintableString serialNumber = new AsnPrintableString();
    public AsnPrintableString countryName = new AsnPrintableString();
    public DirectoryString localityName = new DirectoryString();
    public DirectoryString stateOrProvinceName = new DirectoryString();
    public DirectoryString streetAddress = new DirectoryString();
    public DirectoryString organizationName = new DirectoryString();
    public DirectoryString organizationalUnitName = new DirectoryString();
    public DirectoryString title = new DirectoryString();
    public DirectoryString description = new DirectoryString();
    public DirectoryString businessCategory = new DirectoryString();
    public DirectoryString postalCode = new DirectoryString();
    public DirectoryString postOfficeBox = new DirectoryString();
    public DirectoryString physicalDeliveryOfficeName = new DirectoryString();
    public AsnPrintableString telephoneNumber = new AsnPrintableString();
    public AsnNumericString x121Address = new AsnNumericString();
    public AsnNumericString internationalISDNNumber = new AsnNumericString();
    public AsnPrintableString destinationIndicator = new AsnPrintableString();
    public AsnOctetString userPassword = new AsnOctetString();
    public DirectoryString name = new DirectoryString();
    public DirectoryString givenName = new DirectoryString();
    public DirectoryString generationQualifier = new DirectoryString();
    public DirectoryString initials = new DirectoryString();
    public AsnPrintableString ipAddress = new AsnPrintableString();
    public AsnBitString uniqueIdentifier = new AsnBitString();
    public AsnIA5String emailAddress = new AsnIA5String();
    public AsnIA5String domainNameForm = new AsnIA5String();
    public AsnAny unknown = new AsnAny();
    public SelectedAttributeTypesDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, commonName, (short)0, (int)0x0);
        commonName._boundset(1, 64);
        _setup(commonName, surname, (short)0, (int)0x0);
        surname._boundset(1, 40);
        _setup(surname, serialNumber, (short)0, (int)0x0);
        serialNumber._boundset(1, 64);
        _setup(serialNumber, countryName, (short)0, (int)0x0);
        countryName._boundset(2, 2);
        _setup(countryName, localityName, (short)0, (int)0x0);
        localityName._boundset(1, 128);
        _setup(localityName, stateOrProvinceName, (short)0, (int)0x0);
        stateOrProvinceName._boundset(1, 128);
        _setup(stateOrProvinceName, streetAddress, (short)0, (int)0x0);
        streetAddress._boundset(1, 128);
        _setup(streetAddress, organizationName, (short)0, (int)0x0);
        organizationName._boundset(1, 64);
        _setup(organizationName, organizationalUnitName, (short)0, (int)0x0);
        organizationalUnitName._boundset(1, 64);
        _setup(organizationalUnitName, title, (short)0, (int)0x0);
        title._boundset(1, 64);
        _setup(title, description, (short)0, (int)0x0);
        description._boundset(1, 1024);
        _setup(description, businessCategory, (short)0, (int)0x0);
        businessCategory._boundset(1, 128);
        _setup(businessCategory, postalCode, (short)0, (int)0x0);
        postalCode._boundset(1, 40);
        _setup(postalCode, postOfficeBox, (short)0, (int)0x0);
        postOfficeBox._boundset(1, 40);
        _setup(postOfficeBox, physicalDeliveryOfficeName, (short)0, (int)0x0);
        physicalDeliveryOfficeName._boundset(1, 128);
        _setup(physicalDeliveryOfficeName, telephoneNumber, (short)0, (int)0x0);
        telephoneNumber._boundset(1, 32);
        _setup(telephoneNumber, x121Address, (short)0, (int)0x0);
        x121Address._boundset(1, 15);
        _setup(x121Address, internationalISDNNumber, (short)0, (int)0x0);
        internationalISDNNumber._boundset(1, 16);
        _setup(internationalISDNNumber, destinationIndicator, (short)0, (int)0x0);
        destinationIndicator._boundset(1, 128);
        _setup(destinationIndicator, userPassword, (short)0, (int)0x0);
        userPassword._boundset(1, 128);
        _setup(userPassword, name, (short)0, (int)0x0);
        name._boundset(1, 64);
        _setup(name, givenName, (short)0, (int)0x0);
        givenName._boundset(1, 16);
        _setup(givenName, generationQualifier, (short)0, (int)0x0);
        generationQualifier._boundset(1, 3);
        _setup(generationQualifier, initials, (short)0, (int)0x0);
        initials._boundset(1, 5);
        _setup(initials, ipAddress, (short)0, (int)0x0);
        ipAddress._boundset(1, 256);
        _setup(ipAddress, uniqueIdentifier, (short)0, (int)0x0);
        _setup(uniqueIdentifier, emailAddress, (short)0, (int)0x0);
        emailAddress._boundset(1, 128);
        _setup(emailAddress, domainNameForm, (short)0, (int)0x0);
        _setup(domainNameForm, unknown, (short)0, (int)0x0);
        }
    public SelectedAttributeTypesDefined set(SelectedAttributeTypesDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
