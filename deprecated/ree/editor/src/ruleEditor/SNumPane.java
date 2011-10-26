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

public class SNumPane extends JPanel 
{
  String myName;

  public SNumPane(String name) {
    myName = name;
    initDisplay();
    
  }
  
  public int createRule(Member m) {
    AsnByteArray out = new AsnByteArray(500);
    int lth;

    m.name.write(myName); 
    m.tagtype.write(AsnStatic.ASN_INTEGER); //2    

    if ((lth = m.encode(out)) < 0) {
      System.out.println(myName + " encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } 

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) 
    {
    return true;  
    }
  
  
  private void initDisplay() {
    JLabel label = new JLabel("This number will be assigned by the CA.");
    
    //setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); 
    add(Box.createRigidArea(new Dimension(0,5)));
    add(label);
    //add(Box.createRigidArea(new Dimension(0,5)));
    add(Box.createVerticalGlue());
    if (myName.equals("Serial Number")) {
      setBorder(new TitledBorder(new EtchedBorder(), "  " + myName+" Rule  "));
    }
  }

} 
