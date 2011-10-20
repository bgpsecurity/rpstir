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

public class IssuerPane extends FieldBasePane {
  String[] myAttributeName;
  String[] myAttributeValue;
  JLabel nameLabel;
  JLabel valueLabel;
  JPanel innerPane = new JPanel();
  private JFrame frame;
  private boolean done_redraw = false;
  
  public IssuerPane(String[] attrbuteName, String[] attributeValue) {
    //System.out.println(" In IssuerPane");
    myAttributeName = attrbuteName;
    myAttributeValue = attributeValue;
    initDisplay();
  }

  public IssuerPane() {
    initDisplay();
  }


  public int createRule(Member m) {
    m.name.write("Issuer");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE); 
    m.rule.add();
    SpecialRule s = m.rule.ref.special;
    s.type.write(0x03); //id-subordinate
    s.value.write(0x00); //a full match with active CA is required

    return RuleEditorData.SUCCESS;

  }

  public boolean setRule(Member m) {
    // do nothing
      return true;
  }
  
  private void initDisplay() { 
    setBorder(new TitledBorder(new EtchedBorder(), "  Issurer DN Name  "));
    innerPane.setBorder(BorderFactory.createRaisedBevelBorder());
    //setBorder(new TitledBorder(new EtchedBorder(), "  Issuer Rule  "));
    if (RuleUtils.CAfilename != null)
      {
      RuleUtils.cert = new RenderCA();
      if (!RuleUtils.cert.CAcertRendering()) 
        {
        System.out.println("Failed in IssuerPane.initDisplay");
        return;
        }
      }
    else if (RuleUtils.cert == null)
    {
	RuleUtils.cert = new RenderCA(this);
	RuleUtils.cert.newCA(true, false);
    }

    int n = RuleUtils.cert.getIssuerName().getItemNum();
    innerPane.setLayout(new GridLayout(n, 2, 10, 10));
    for (int i = 0; i < n; i++) {
      String name = RuleUtils.cert.getIssuerName().getDNname(i);
      String value = RuleUtils.cert.getIssuerName().getDNvalue(i);
      //System.out.println(" DN: " + name + " " + value);
      nameLabel = new JLabel(name + ":");
      nameLabel.setFont(new java.awt.Font("Dialog", 1, 12));
      valueLabel = new JLabel(value); 
      innerPane.add(nameLabel);
      innerPane.add(valueLabel);
    } 
    add(innerPane);
  } 

  public void updateCAInfo() {
    while (RuleUtils.cert == null) {
	/*
      JOptionPane.showMessageDialog(frame, 
       	   "No active CA.  Please click on \"Retrieve CA's Certificate File \" first, \nthen select other fields, and come back to this field", 
       	    "", JOptionPane.WARNING_MESSAGE); 
	*/
      return;
    } 
    innerPane.removeAll();

    int n = RuleUtils.cert.getIssuerName().getItemNum();
    innerPane.setLayout(new GridLayout(n, 2, 10, 10));
    //System.out.println(" In Issuer redraw()");
    for (int i = 0; i < n; i++) {
      String name = RuleUtils.cert.getIssuerName().getDNname(i);
      String value = RuleUtils.cert.getIssuerName().getDNvalue(i);
      //System.out.println(" DN: " + name + " " + value);
      nameLabel = new JLabel(name + ":");
      nameLabel.setFont(new java.awt.Font("Dialog", 1, 12));
      valueLabel = new JLabel(value); 
      innerPane.add(nameLabel);
      innerPane.add(valueLabel);
    } 
    //innerPane.setBorder(BorderFactory.createRaisedBevelBorder());
    revalidate();
    repaint();
  }
  
} // IssuerPane

