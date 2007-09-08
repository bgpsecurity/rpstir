/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Marla Shepard, Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

package ruleEditor;

import ruleEditor.*;
import rules.*;
import asn.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class AlternativeNamePane extends ExtnFieldBasePane 
    implements NameListener
{
    //GeneralNamePane pane;
    NamePane pane;
    int[] choiceState;
    int[] tags;
    int numProhibited;

    static public int PROHIBIT = 1;

  public AlternativeNamePane(String title) {
    this(title, null, null);  
  }

  public AlternativeNamePane(String title, String criticalFlag) {
    this(title, criticalFlag, null);  
  }

  public AlternativeNamePane(String title, String criticalFlag,  String type) 
    {
    super(title, criticalFlag, type);
    // System.out.println("Altname constr " + title + " flag " + criticalFlag);  
    numProhibited = 0;
    choiceState = new int[RuleEditorData.SubjAltNameFields.length];
    for (int i=0; i< RuleEditorData.SubjAltNameFields.length; i++)
	choiceState[i] = 0;
    tags = new int[RuleEditorData.SubjAltNameFields.length];
    tags[0] = 0xA4;
    tags[1] = 0x81;
    tags[2] = 0x87;
    tags[3] = 0x82;
  }

  public void setLastToRequire()
  {
      int len = RuleEditorData.SubjAltNameFields.length;
      if (numProhibited == len - 1)
      {
	  for (int index = 0; index < len; index++)
	  {
	      if (pane.getChoice(index) == RuleEditorData.ALLOW)
		  pane.setChoice(index, RuleEditorData.REQUIRE);
	  }
      }
  }
   
  public void namePerformed(NameEvent e){
	NamePane np = (NamePane)e.getSource();
	String command = np.getNameCommand();
	int index = np.getIndexCommand();
	//System.out.println("AltNamePane performed command " + command);
	String choice = np.getChoice(index);
	if (choiceState == null)
	    return;
	if (choice.compareTo(RuleEditorData.PROHIBIT) == 0)
	{
	    if (numProhibited == RuleEditorData.SubjAltNameFields.length - 1)
	    {
	      np.setChoice(index,RuleEditorData.REQUIRE);
	      JOptionPane.showMessageDialog(null,"Cannot prohibit all fields.",
					    "Prohibit limit exceded",
					    JOptionPane.WARNING_MESSAGE);
	    }
	    else if (choiceState[index] != PROHIBIT)
	    {
		numProhibited++;
		choiceState[index] = PROHIBIT;
	    }
	} else
	{
	    if (choiceState[index] == PROHIBIT)
	    {
		numProhibited--;
		choiceState[index] = 0;
	    }
	}
	setLastToRequire();
    }
 
    /*** 
       WARNING!!!
       setContentPane is called before the constructor as 
       it is called from ExtnFieldBasePane's constructor 
    ***/

  public void setContentPane() {
      //pane = new GeneralNamePane(myName, myType);
    pane = new NamePane(RuleEditorData.SubjAltNameFields, false);
    pane.addNameListener(this);
    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    contentPane.add(pane);    
    contentPane.add(Box.createVerticalGlue());
  }

  
  public int createRule(Member m) 
    {
    //System.out.println("Alt pane createRule");
    m.name.write(RuleEditorData.SUBJ_ALT_NAME);
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
    SetSeqOfRule sso = m.rule.ref.seqOf;
    sso.member.name.write(RuleEditorData.GENERAL_NAMES);
    sso.member.rule.add();
    Members mm = sso.member.rule.ref.choice;    
    int j = 0, k = 0;
    for (int i = 0; i < pane.length(); i++)
        {
        if (pane.getChoice(i) == RuleEditorData.PROHIBIT) continue;
        if (pane.getChoice(i) == RuleEditorData.REQUIRE) k++;
        mm.member.index(j).insert();
        Member m1 = mm.member.index(j++);
        m1.name.write(RuleEditorData.SubjAltNameFields[i]);
        m1.tagtype.write(tags[i]);
        }
    if (k > 0)
        {
        sso.groupRules.groupRule.index(0).insert();
        GroupRule gr = sso.groupRules.groupRule.index(0);
        gr.name.write("Required Alt Names");
        gr.thencase.rule.add();
        SpecialRule s = gr.thencase.rule.ref.special;
        s.type.write(7);  //id-limits
        s.value.limits.location.path.write("da");
        int index = -1;
        for (int i = 0; i < pane.length(); i++)
            {
            if (pane.getChoice(i) == RuleEditorData.REQUIRE)
                {
                s.value.limits.valAndLimit.idAndLimit.index(++index).insert();
                IdAndLimit il = (IdAndLimit)s.value.limits.valAndLimit.idAndLimit.index(index);
                il.id.tag.write(tags[i]);
                il.max.write(1); 
                il.min.write(1);
                }
            }
        }
    return RuleEditorData.SUCCESS;
    }

  public boolean setRule(Member m) 
    {
    if (m.rule == null || m.rule.ref == null || m.rule.ref.seqOf == null ||
        m.rule.ref.seqOf.member == null) return true;
    SetSeqOfRule sso = m.rule.ref.seqOf;
    if (sso.member == null || sso.member.rule == null || 
        sso.member.rule.ref == null || sso.member.rule.ref.choice == null) 
        return true;
    Members mm = sso.member.rule.ref.choice;
    for (int i = 0; i < RuleEditorData.SubjAltNameFields.length;
        pane.setChoice(i++, RuleEditorData.PROHIBIT));
    for (int i = 0; i < mm.numitems(); i++)
        {
        Member m1 = mm.member.index(i);
        if (m1 == null || m1.name == null) break;
        AsnByteArray aba = new AsnByteArray();
        m1.name.read(aba);
        for (int j = 0; j < pane.length(); j++)
            {
            if (pane.getCommand(j).compareTo(aba.toString()) == 0)
                {
                pane.setChoice(j, RuleEditorData.ALLOW);
                break;
                }
            }    
        }
    if (sso.groupRules == null || sso.groupRules.numitems() == 0) return true;
    GroupRule gr = sso.groupRules.groupRule.index(0);
    if (gr.thencase == null || gr.thencase.rule == null ||
        gr.thencase.rule.ref == null ||
        gr.thencase.rule.ref.special == null) return true;
    SpecialRule s = gr.thencase.rule.ref.special;
    int k;
    if (s.value == null || s.value.limits == null ||
        s.value.limits.valAndLimit == null ||
        (k = s.value.limits.valAndLimit.numitems()) == 0) return true;
    IdAndLimits idals = s.value.limits.valAndLimit;
    for (int j = 0; j < k; j++)
        {
        IdAndLimit idal = idals.idAndLimit.index(j);
        AsnIntRef tagref = new AsnIntRef();
        idal.id.tag.read(tagref);
        for (int i = 0; i < pane.length(); i++)
            {
            if (tagref.val == tags[i])
                {
                pane.setChoice(i, RuleEditorData.REQUIRE);
                break;
                }
            }
        }
    return true;
    }
}
