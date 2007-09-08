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

public class CertSeriNumPane extends FieldBasePane {
  String myName = "User Certificate Serial Number";

  public CertSeriNumPane() {
      initDisplay();
  }

  public int createRule(Member m) {
    m.name.write(myName); 
    m.tagtype.write(AsnStatic.ASN_INTEGER); //0x00A0    

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
    // do nothing
      return true;
  }

  private void initDisplay() { 
    JPanel pane = RuleUtils.getInnerPane(myName + " should be an integer.");
    add(pane);
    setBorder(new TitledBorder(new EtchedBorder(), "   " + myName + " Rule "));

  } 

}
