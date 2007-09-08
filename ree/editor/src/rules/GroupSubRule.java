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
public class GroupSubRule extends AsnSequence
    {
    public Locations locations = new Locations();
    public AsnBoolean negate = new AsnBoolean();
    public _RuleChoice rule = new _RuleChoice();
    public GroupSubRule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, locations, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(locations, negate, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(negate, rule, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_POINTER_FLAG), (int)0x0);
        }
    public GroupSubRule set(GroupSubRule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
