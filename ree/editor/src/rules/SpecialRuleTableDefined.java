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
public class SpecialRuleTableDefined extends AsnChoice
    {
    public AsnNone set_num = new AsnNone();
    public AsnNone check_CRLNum = new AsnNone();
    public AsnInteger subordinate = new AsnInteger();
    public KeyIDMethod keyIDMethod = new KeyIDMethod();
    public AsnNone isForCA = new AsnNone();
    public AsnNone allowIFFCA = new AsnNone();
    public LimitIds limits = new LimitIds();
    public Ranges addrRanges = new Ranges();
    public SpecialRuleTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, set_num, (short)0, (int)0x0);
        _setup(set_num, check_CRLNum, (short)0, (int)0x0);
        _setup(check_CRLNum, subordinate, (short)0, (int)0x0);
        _setup(subordinate, keyIDMethod, (short)0, (int)0x0);
        _setup(keyIDMethod, isForCA, (short)0, (int)0x0);
        _setup(isForCA, allowIFFCA, (short)0, (int)0x0);
        _setup(allowIFFCA, limits, (short)0, (int)0x0);
        _setup(limits, addrRanges, (short)0, (int)0x0);
        }
    public SpecialRuleTableDefined set(SpecialRuleTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
