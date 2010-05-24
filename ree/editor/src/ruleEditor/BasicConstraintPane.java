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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
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

public class BasicConstraintPane extends ExtnFieldBasePane 
implements ActionListener,
	   RuleListener {
  private String bcChoice;
  private int pLth;
  private ThreeWayCombo bc;
  JLabel label;
  private JTextField pathLth;

  public BasicConstraintPane() {
    super("Basic Constraints", RuleEditorData.REQUIRE);
  }

  private void disableFields() {
    label.setEnabled(false);
    pathLth.setEnabled(false);
  }

  private void enableFields() {
    label.setEnabled(true);
    pathLth.setEnabled(true);
  }

  private void formUnitPane(JPanel pane,
			    JLabel label,
			    JTextField text) {
    pane.add(label);
    pane.add(text);
    text.setPreferredSize(RuleEditorData.shortField);
    text.setMinimumSize(RuleEditorData.shortField);
    text.setMaximumSize(RuleEditorData.shortField);
    text.addActionListener(this);
  }

  public void setContentPane() {
      /*
    label = new JLabel("Please enter the maximum path length: ");
    pathLth = new JTextField();
    JPanel pane = new JPanel();
    formUnitPane(pane, label, pathLth);
    pane.setAlignmentX(Component.RIGHT_ALIGNMENT); 
    bc = new ThreeWayCombo("Path length constraint ?", 
			   RuleEditorData.PROHIBIT);
    bc.addRuleListener(this);
    bc.setAlignmentX(Component.RIGHT_ALIGNMENT); 

    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    contentPane.add(Box.createRigidArea(new Dimension(0,10)));
    contentPane.add(new JLabel());
    contentPane.add(bc);
    contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    contentPane.add(pane);
    contentPane.add(Box.createVerticalGlue());
      */
  }

  public void rulePerformed(RuleEvent e) {
      /*
    bcChoice = ((ThreeWayCombo)e.getSource()).getChoice();
    //System.out.println(" bcChoice: " + bcChoice);
    if (bcChoice.equals(RuleEditorData.PROHIBIT)) {
      disableFields();
    } else {
      enableFields();
    }
      */
  }

  public void actionPerformed(java.awt.event.ActionEvent e) {
    pLth = Integer.parseInt(((JTextField)e.getSource()).getText().trim());
    System.out.println(" path length: " + pLth);
  }
  
  public int createRule(Member m) {
    m.name.write("Basic Constraints");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
    m.rule.ref.sequence.members.member.index(0).insert();
    Member m1 = m.rule.ref.sequence.members.member.index(0);

    m1.name.write("cA");
    m1.tagtype.write(AsnStatic.ASN_BOOLEAN);
    m1.rule.add();
    Rule p = m1.rule.ref.primitive;
    p.targets.require.target.index(0).insert();
    p.targets.require.target.index(0).num.write(-1);

    /*
    bcChoice = bc.getChoice();
    if (!bcChoice.equals(RuleEditorData.PROHIBIT)) {
      m.rule.ref.sequence.members.member.index(1).insert();
      Member m2 = m.rule.ref.sequence.members.member.index(1);
      m2.name.write("pathLenconstraint");
      m2.tagtype.write(AsnStatic.ASN_INTEGER);
      m2.rule.add();
      m2.rule.ref.primitive.targets.allow.target.index(0).insert();
      m2.rule.ref.primitive.targets.allow.target.index(0).range.lo.number.write(0);
      m2.rule.ref.primitive.targets.allow.target.index(0).range.hi.number.write(pLth);

      if (bcChoice.equals(RuleEditorData.ALLOW)) {
	m2.optional.write(AsnStatic.ASN_BOOL_TRUE); // 
      }
    
    }
    */
    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
      return true;
      /*  Rule will be hard-coded, so don't need to read it now 
    AsnIntRef value = new AsnIntRef();

    Members M = m.rule.ref.sequence.members;
    int ni = M.numitems();
    if (ni == 2) { // path length contraint exists
     Member m2 = m.rule.ref.sequence.members.member.index(1);
     m2.siz.hi.number.read(value); 
     pLth = value.val;
     if (m2.optional != null) { // opetional exists, allow
       bcChoice = RuleEditorData.ALLOW;
     } else {
       bcChoice = RuleEditorData.REQUIRE;
     }
    } else { 
      bcChoice = RuleEditorData.PROHIBIT;
    }

    bc.setChoice(bcChoice);
    pathLth.setText(Integer.toString(pLth));
      */
  }
      
}

