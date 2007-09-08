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

public class SKIPane extends ExtnFieldBasePane 
implements ActionListener {

    /*
  String myChoice = "160";  // default
  private JRadioButton sha160Button;
  private JRadioButton sha60Button;
  private JRadioButton anyButton;
    */

  public SKIPane(String type) {
    super("Subject Key Identifier", RuleEditorData.PROHIBIT, type);
  }

    /*
  public String getChoice() {
    return myChoice;
  }

  public void setChoice(String choice) {
      myChoice = choice;
      if (choice.equals("160")) {
      sha160Button.setSelected(true);
    } else if (choice.equals("60")) {
      sha60Button.setSelected(true);
    } else if (choice.equals("any")) {
      anyButton.setSelected(true);
    } 
  }
    */

  public void setContentPane() {
    JLabel label = new JLabel("The Subject Key Identifier will be produced by "
			 +  " 160-bit SHA-1 hash of the subject's public key");

    JPanel innerPane = new JPanel();
    /*
    sha160Button = new JRadioButton(" 160 -bit SHA-1 hash");
    sha160Button.setActionCommand("160");
    sha160Button.setSelected(true); // default
    sha160Button.addActionListener(this);
    sha60Button = new JRadioButton(" Least significant 60 bits of SHA-1 hash");
    sha60Button.setActionCommand("60");
    sha60Button.setSelected(false);
    sha60Button.addActionListener(this);
    anyButton = new JRadioButton(" Any");
    anyButton.setActionCommand("any");
    anyButton.setSelected(false);
    anyButton.addActionListener(this);

    ButtonGroup groupButton = new ButtonGroup();
    groupButton.add(sha160Button);
    groupButton.add(sha60Button);
    groupButton.add(anyButton);
    */
  
    //contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    contentPane.add(label);
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    //contentPane.add(innerPane);
    //contentPane.add(Box.createVerticalGlue());
    //contentPane.setBorder(new TitledBorder(new EtchedBorder(), "  Serial Number Rule  "));

  }

  public void actionPerformed(java.awt.event.ActionEvent e) {
      //myChoice = e.getActionCommand();
    //System.out.println("SKI choice: " + myChoice);
  }

  public int createRule(Member m) {
    m.name.write("Subject Key Identifier");
    m.tagtype.write(AsnStatic.ASN_OCTETSTRING);
    m.rule.add();
    SpecialRule s = m.rule.ref.special;
    s.type.write(RulesStatic.id_keyIDMethod); //id-keyIDMethod

    s.value.keyIDMethod.keyHash.write(RulesStatic.id_key_sha1);   // SHA-1 hash method
    s.value.keyIDMethod.location.path.write("td6d1"); 
    // from top(t), go down 1(d), then to 6th item(6), which is SubjectPublicKeyInfo
    // then go down one level(d), move to next item(1), which is SubjectPublicKey

    return RuleEditorData.SUCCESS;
    
  }

  public boolean setRule(Member m) 
    {
    return true;
 /*  Rule will be hard-coded, so need not set up choice
    AsnIntRef value = new AsnIntRef();
    SpecialRule s = m.rule.ref.special;
    s.value.keyIDMethod.keyHash.read(value);

    switch (value.val) 
      {
    case RulesStatic.id_key_snum: myChoice = "160"; break;
    case RulesStatic.id_key_sha1: myChoice = "160"; break;
    case RulesStatic.id_trunc_sha1: myChoice = "60"; break;
    case RulesStatic.id_keu_uniq_val: myChoice = "any"; break;
    default:
       JOptionPane.showMessageDialog(frame, "Invalid choice in SKIPane rule set"); 
        return false;
      }
    
    setChoice(myChoice);
    return true;
    */
    }
 
}
