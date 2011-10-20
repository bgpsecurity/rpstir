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
public class Member extends AsnArray
    {
    public AsnUTF8String name = new AsnUTF8String();
    public AsnInteger tagtype = new AsnInteger();
    public AsnBoolean optional = new AsnBoolean();
    public Range siz = new Range();
    public _RuleChoice rule = new _RuleChoice();
    public Member()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(name, tagtype, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(tagtype, optional, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(optional, siz, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(siz, rule, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_POINTER_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        Member objp = new Member();
        _set_pointers(objp);
        return objp;
        }

    public Member index(int index)
        {
        return (Member)_index_op(index);
        }

    public Member set(Member frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
