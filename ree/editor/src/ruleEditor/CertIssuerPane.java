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

public class CertIssuerPane extends ExtnFieldBasePane 
implements RuleListener {
  String myName;
  String name;
  

  public CertIssuerPane() {
    super("Certificate Issuer", RuleEditorData.REQUIRE); 
    myName = "Certificate Issuer";
  }

  public String getChoice() {

    return name;
  }
  
  public int createRule(Member m) {

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
    // nothing to do
      return true;
  }
  
  public void setContentPane() {
    JLabel label = new JLabel("  This extension is associated with indrect CRL.");
    label.setFont(new java.awt.Font("Dialog", 1, 12));
    contentPane.add(new JLabel(""));
    contentPane.add(new JLabel(""));
    contentPane.add(label);

  }

  public void rulePerformed(RuleEvent e) {

  }

}
