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
public class NamedBits extends AsnSequence
    {
    public Target forbid = new Target();
    public Target require = new Target();
    public GroupRules groupRules = new GroupRules();
    public NamedBits()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, forbid, (short)0, (int)0x0);
        _setup(forbid, require, (short)0, (int)0x0);
        _setup(require, groupRules, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public NamedBits set(NamedBits frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
