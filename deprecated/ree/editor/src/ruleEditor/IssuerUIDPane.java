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

public class IssuerUIDPane extends FieldBasePane {
  
  public IssuerUIDPane() {
    initDisplay();
  }

  public int createRule(Member m) {
    m.name.write("Issuer Unique ID");
 //   m.tagtype.write(AsnStatic.ASN_CONT_SPEC | 1); //0x0081    
    m.tagtype.write(AsnStatic.ASN_NONE); //0x0101    
    m.optional.write(AsnStatic.ASN_BOOL_TRUE);

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
      return true;
  }

  
  private void initDisplay() {
    JLabel label = new JLabel(
			      "There is no Subject Unique ID in this issuer cert, so this field is not allowed.");
    label.setBorder(new EmptyBorder(20, 20, 5, 5));
    add(label);
    setBorder(new TitledBorder(new EtchedBorder(), "  Issuer Unique ID Rule  "));
    
  }
  
} // IssuerUIDpane 
					  
