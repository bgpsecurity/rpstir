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

public class AKIPane extends ExtnFieldBasePane 
implements RuleListener {
  private String skiChoice;
  private int choiceIndex = -1;
  private ThreeWayCombo ski;
  private ThreeWayCombo nameSerial;
  private JFrame frame;

  public AKIPane(String name, String type) {
    super(name, RuleEditorData.PROHIBIT, type);
  }

  public void setContentPane() {
    JPanel innerPane = new JPanel();
    JRadioButton skiButton = new JRadioButton(" Issuer subject key identifier");

    ski = new ThreeWayCombo(" Issuer subject key identifier: ",
			      RuleEditorData.REQUIRE,
			      new Dimension(240,20), 
			      RuleEditorData.longField);
    ski.setEnabled(false);
    skiChoice =  ski.getChoice();
    ski.setRuleCommand("ski");
    ski.addRuleListener(this);
    
    innerPane.setLayout(new BoxLayout(innerPane, BoxLayout.Y_AXIS));
    //innerPane.add(Box.createRigidArea(new Dimension(0,5)));
    innerPane.add(ski);
    innerPane.add(Box.createRigidArea(new Dimension(0,5)));
    innerPane.setBorder(new EmptyBorder(10, 10, 20, 10));

    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    //contentPane.add(label);
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    contentPane.add(innerPane);
    contentPane.add(Box.createVerticalGlue());
  }

  public void rulePerformed(RuleEvent e) {
      String command = ((ThreeWayCombo)e.getSource()).getRuleCommand();
      if (command == "ski") {
	skiChoice = ((ThreeWayCombo)e.getSource()).getChoice();
      }
      //System.out.println(" AKI choice: " + myChoice[0] + " " + myChoice[1]);
    }

  public int createRule(Member m) {
    AsnByteArray aba;
    Targets t;
    m.name.write("Authority Key Identifier");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
    Members M = m.rule.ref.sequence.members;
    int ind = -1;
    if (skiChoice != RuleEditorData.PROHIBIT) {
      M.member.index(++ind).insert();
      M.member.index(ind).name.write("keyIdentifier");
      M.member.index(ind).tagtype.write(AsnStatic.ASN_CONT_SPEC);
//      M.member.index(ind).optional.write(AsnStatic.ASN_BOOL_TRUE);
      if (RuleUtils.cert.getSubjectKeyId() != null) {
	M.member.index(ind).rule.add();
	t = M.member.index(ind).rule.ref.primitive.targets.require;
	t.target.index(0).insert();
	aba = new AsnByteArray(RuleUtils.cert.getSubjectKeyId(), RuleUtils.cert.getSubjectKeyId().length);
	t.target.index(0).value.write(aba);
      } else { // ERROR
	JOptionPane.showMessageDialog(frame,
				      "There is no Subject Key Identifier extension in issuer cert",
				      "", JOptionPane.ERROR_MESSAGE); 
	return RuleEditorData.FAILED;
      }
    }
   
    return RuleEditorData.SUCCESS;
  }
  
  public boolean setRule(Member m) 
    {
    // System.out.println("in setRule for AKI");
    AsnIntRef value = new AsnIntRef();
    if (m.rule == null || m.rule.ref == null || m.rule.ref.sequence == null ||
      m.rule.ref.sequence.members == null || m.rule.ref.sequence.members.numitems() == 0)
      return false;
    Members mm = m.rule.ref.sequence.members;
    Member m1 = mm.member.index(0);
    if (m1.rule == null || m1.rule.ref == null || m1.rule.ref.primitive == null ||
      m1.rule.ref.primitive.targets == null) return false;
         // can only have one choice here 
    ForbidAllowRequire far = m1.rule.ref.primitive.targets;
    if (far.forbid != null && far.forbid.numitems() > 0) 
      skiChoice = RuleEditorData.PROHIBIT;
    else if (far.allow != null && far.allow.numitems() > 0) 
      skiChoice = RuleEditorData.ALLOW;
    else if (far.require != null && far.require.numitems() > 0) 
      skiChoice = RuleEditorData.REQUIRE;
    
    ski.setChoice(skiChoice);
    return true;
    }
 
}
