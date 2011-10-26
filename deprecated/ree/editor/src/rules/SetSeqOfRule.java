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
public class SetSeqOfRule extends AsnSequence
    {
    public Member member = new Member();
    public AsnInteger min = new AsnInteger();
    public AsnInteger max = new AsnInteger();
    public GroupRules groupRules = new GroupRules();
    public SetSeqOfRule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, member, (short)0, (int)0x0);
        _setup(member, min, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(min, max, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        _setup(max, groupRules, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public SetSeqOfRule set(SetSeqOfRule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
