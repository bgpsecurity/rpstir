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

public class SubjectUIDPane extends FieldBasePane {
  
  public SubjectUIDPane() {
    initDisplay();
  }

  public int createRule(Member m) {
    m.name.write("Subject Unique ID");
 //   m.tagtype.write(AsnStatic.ASN_CONT_SPEC | 2); //0x0082    
    m.tagtype.write(AsnStatic.ASN_NONE); //0x0101    
    m.optional.write(AsnStatic.ASN_BOOL_TRUE);

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
      return true;
  }
  
  private void initDisplay() {
    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    JPanel innerPane = new JPanel();
    innerPane.setLayout(new BoxLayout(innerPane, BoxLayout.X_AXIS));
    //innerPane.setLayout(new GridLayout(1, 2));
    JLabel label = new JLabel
      ("      Please check this field's availability:", JLabel.LEFT);
    //label.setBorder(BorderFactory.createRaisedBevelBorder());
    //label.setAlignmentX(Component.LEFT_ALIGNMENT);
    //label.setMinimumSize(longerField);
    //label.setPreferredSize(longerField);
    //innerPane.add(Box.createRigidArea(new Dimension(5,0)));
    //innerPane.add(label);
    //innerPane.add(Box.createRigidArea(new Dimension(5, 0)));
    ThreeWayCombo QAPane = new ThreeWayCombo("Please check this field's availability:", 
					     false,
					     new Dimension(240,20), 
					     RuleEditorData.longField);
    //QAPane.setBorder(BorderFactory.createRaisedBevelBorder());
    //QAPane.setMinimumSize(shorterField);
    //QAPane.setPreferredSize(shorterField);
    
    innerPane.add(QAPane);
    
    add(Box.createRigidArea(new Dimension(0, 20)));
    add(innerPane);
    add(Box.createVerticalGlue());
    setBorder(new TitledBorder(new EtchedBorder(), "  Subject Unique ID Rule  "));
    
  }
    
}
