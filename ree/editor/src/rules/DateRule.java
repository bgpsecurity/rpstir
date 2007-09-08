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
package rules;
import name.*;
import asn.*;
public class DateRule extends AsnSequence
    {
    public AsnInteger min = new AsnInteger();
    public AsnBoolean momin = new AsnBoolean();
    public AsnInteger max = new AsnInteger();
    public AsnBoolean momax = new AsnBoolean();
    public AsnPrintableString ref = new AsnPrintableString();
    public DateRule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, min, (short)0, (int)0x0);
        _setup(min, momin, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(momin, max, (short)0, (int)0x0);
        _setup(max, momax, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(momax, ref, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public DateRule set(DateRule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
