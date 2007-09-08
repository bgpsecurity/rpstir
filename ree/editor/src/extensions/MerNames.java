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
public class MerNames extends AsnArray
    {
    public AsnVisibleString language = new AsnVisibleString();
    public NameInMerNames name = new NameInMerNames();
    public CityInMerNames city = new CityInMerNames();
    public StateProvinceInMerNames stateProvince = new StateProvinceInMerNames();
    public PostalCodeInMerNames postalCode = new PostalCodeInMerNames();
    public CountryNameInMerNames countryName = new CountryNameInMerNames();
    public MerNames()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, language, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        language._boundset(1, 35);
        _setup(language, name, (short)(AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA1);
        _setup(name, city, (short)(AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA2);
        _setup(city, stateProvince, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA3);
        _setup(stateProvince, postalCode, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA4);
        _setup(postalCode, countryName, (short)(AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA5);
        }
    public AsnObj _dup()
        {
        MerNames objp = new MerNames();
        _set_pointers(objp);
        return objp;
        }

    public MerNames index(int index)
        {
        return (MerNames)_index_op(index);
        }

    public MerNames set(MerNames frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
