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
public class RuleChoice extends AsnArray
    {
    public CompoundRule sequence = new CompoundRule();
    public CompoundRule set = new CompoundRule();
    public CompoundRule definerSeq = new CompoundRule();
    public SetSeqOfRule seqOf = new SetSeqOfRule();
    public SetSeqOfRule setOf = new SetSeqOfRule();
    public Members choice = new Members();
    public Members definedBy = new Members();
    public Rule primitive = new Rule();
    public Rule definerRule = new Rule();
    public DateRule date = new DateRule();
    public NamedBits namedBits = new NamedBits();
    public FileRef fileRef = new FileRef();
    public Wrapper wrapper = new Wrapper();
    public SpecialRule special = new SpecialRule();
    public AsnNull none = new AsnNull();
    public RuleChoice()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, sequence, (short)0, (int)0xE0);
        _setup(sequence, set, (short)0, (int)0xE1);
        _setup(set, definerSeq, (short)0, (int)0xE2);
        _setup(definerSeq, seqOf, (short)0, (int)0xE3);
        _setup(seqOf, setOf, (short)0, (int)0xE4);
        _setup(setOf, choice, (short)0, (int)0xE5);
        _setup(choice, definedBy, (short)0, (int)0xE6);
        _setup(definedBy, primitive, (short)0, (int)0xE7);
        _setup(primitive, definerRule, (short)0, (int)0xE8);
        _setup(definerRule, date, (short)0, (int)0xE9);
        _setup(date, namedBits, (short)0, (int)0xEA);
        _setup(namedBits, fileRef, (short)0, (int)0xEB);
        _setup(fileRef, wrapper, (short)0, (int)0xEC);
        _setup(wrapper, special, (short)0, (int)0xED);
        _setup(special, none, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        RuleChoice objp = new RuleChoice();
        _set_pointers(objp);
        return objp;
        }

    public RuleChoice index(int index)
        {
        return (RuleChoice)_index_op(index);
        }

    public RuleChoice set(RuleChoice frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
