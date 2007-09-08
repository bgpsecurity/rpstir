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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class RuleSet extends AsnArray
    {
    public RuleType type = new RuleType();
    public RuleGroup ruleGroup = new RuleGroup();
    public RuleSet()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type, (short)0, (int)0x0);
        _setup(type, ruleGroup, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        RuleSet objp = new RuleSet();
        _set_pointers(objp);
        return objp;
        }

    public RuleSet index(int index)
        {
        return (RuleSet)_index_op(index);
        }

    public RuleSet set(RuleSet frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
