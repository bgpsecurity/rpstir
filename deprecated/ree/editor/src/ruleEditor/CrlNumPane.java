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

public class CrlNumPane extends ExtnFieldBasePane {
  SNumPane numPane;

  public CrlNumPane() {
    super("CRL Number", RuleEditorData.PROHIBIT);
  }
  
  
  public int createRule(Member m) {
    return(numPane.createRule(m));
  }

  public boolean setRule(Member m) {
    numPane.setRule(m);
    return true;
  }
  
  public void setContentPane() {
    numPane = new SNumPane("CRL Number");
    contentPane.add(numPane);
  }

}
