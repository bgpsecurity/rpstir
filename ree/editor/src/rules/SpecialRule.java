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
package rules;
import name.*;
import asn.*;
public class SpecialRule extends AsnSequence
    {
    public SpecialRuleTableInSpecialRule type = new SpecialRuleTableInSpecialRule();
    public SpecialRuleTableDefined value = new SpecialRuleTableDefined();
    public SpecialRule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type, (short)0, (int)0x0);
        _setup(type, value, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public SpecialRule set(SpecialRule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
