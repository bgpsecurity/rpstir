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

public class InvDatePane extends ExtnFieldBasePane {
  String name;

  public InvDatePane() {
    super("Invalidity Date", RuleEditorData.PROHIBIT); 
  }

  public String getChoice() {

    return name;
  }
  
  public int createRule(Member m) {
    AsnByteArray out = new AsnByteArray(500);
    int lth;

    m.name.write(myName); 
    m.tagtype.write(AsnStatic.ASN_GENTIME); //0x18
    m.rule.add();
    DateRule d = (DateRule)m.rule.ref.date;// DateRule 
    d.min.write(-99);
    d.momin.write(AsnStatic.ASN_BOOL_TRUE); 
    d.max.write(0);
    d.ref.write(""); // Reference to current

    if ((lth = m.encode(out)) < 0) {
      System.out.println(myName + " encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } 

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) { 
    // do nothing
      return true;
  }
  
  public void setContentPane() {
    JLabel label = new JLabel(myName + " should precede the current time.");
    label.setFont(new java.awt.Font("Dialog", 1, 12));
    contentPane.add(label);
  }

}
