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
public class Rule extends AsnSequence
    {
    public AsnBoolean least_first = new AsnBoolean();
    public ForbidAllowRequire targets = new ForbidAllowRequire();
    public _RuleChoice rule = new _RuleChoice();
    public Rule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, least_first, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(least_first, targets, (short)0, (int)0x0);
        _setup(targets, rule, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_POINTER_FLAG), (int)0x0);
        }
    public Rule set(Rule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
