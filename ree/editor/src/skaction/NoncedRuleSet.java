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
public class NoncedRuleSet extends AsnArray
    {
    public NumOrTime nonce = new NumOrTime();
    public RuleSet ruleSet = new RuleSet();
    public NoncedRuleSet()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, nonce, (short)0, (int)0x0);
        _setup(nonce, ruleSet, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        NoncedRuleSet objp = new NoncedRuleSet();
        _set_pointers(objp);
        return objp;
        }

    public NoncedRuleSet index(int index)
        {
        return (NoncedRuleSet)_index_op(index);
        }

    public NoncedRuleSet set(NoncedRuleSet frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
