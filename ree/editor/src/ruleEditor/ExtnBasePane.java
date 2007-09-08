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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

abstract class ExtnBasePane extends FieldBasePane {
  private String myLabel = null;
  private JSplitPane mySplitPane = null;

  public ExtnBasePane(String name) {
    myLabel = name;
    mySplitPane = null;
  }

  public void setSplitPane(JSplitPane splitPane) {
    mySplitPane = splitPane;
  }

  public boolean init() {
    if (mySplitPane == null) {
      return true;
    }
    try {
      initDisplay();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  private void initDisplay() {
    JLabel label = new JLabel(myLabel);
    label.setHorizontalAlignment(SwingConstants.CENTER);
    mySplitPane.setOneTouchExpandable(true);
    mySplitPane.setDividerSize(5);
    mySplitPane.setContinuousLayout(true);
    add(mySplitPane);
    setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
    if (myLabel.equals("Revoked Certificates")) {
      setBorder(new TitledBorder(new EtchedBorder(),  " " + myLabel + " Rule  "));
    } else {
      setBorder(new TitledBorder(new EtchedBorder(),  " " + myLabel + " Extensions Rule  "));
    }
  }

}
