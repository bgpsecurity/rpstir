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
import skaction.*;
import Algorithms.*;
import name.*;
import certificate.*;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

abstract class CommandPane extends JPanel{
  private String myLabel = null;
  private JSplitPane mySplitPane = null;
  public String type;
  public Certificate cert = new Certificate();
  public SKAction skaction = new SKAction();
  public RuleChoice rc = new RuleChoice();
  public String keyName;
  public String ruleName;

  public abstract int createRule(String filename);
  public abstract boolean setRule(RuleChoice rc);
    //public abstract void redraw();

  //Create a file chooser
  JFileChooser fc = new JFileChooser(RuleUtils.RootDir);


  public CommandPane(String name) {
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
    label.setFont(new java.awt.Font("Dialog", 1, 14));
    label.setHorizontalAlignment(SwingConstants.CENTER);
    mySplitPane.setOneTouchExpandable(true);
    mySplitPane.setDividerSize(5/*10*/);
    mySplitPane.setContinuousLayout(true);
    //mySplitPane.setLeftComponent(lPane);
    //mySplitPane.setRightComponent(rPane);

    /*
    JButton rcButton = new JButton(" Retrieve CA's Certificate File ");
    rcButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //rcButton.setPreferredSize(new Dimension(100, 30));
    rcButton.setActionCommand("rc");
    rcButton.addActionListener(this);
    //rcButton.setBorder(BorderFactory.createRaisedBevelBorder());
    JButton rrButton = new JButton(" Retrieve Rule File ");
    rrButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //rrButton.setPreferredSize(new Dimension(100, 30));
    rrButton.setActionCommand("rr");
    rrButton.addActionListener(this);
    //rrButton.setBorder(BorderFactory.createRaisedBevelBorder());
    JButton crButton = new JButton(" Create Rule and Save to File ");
    crButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //crButton.setPreferredSize(new Dimension(100, 30));
    crButton.setActionCommand("cr");
    crButton.addActionListener(this);
    //crButton.setBorder(BorderFactory.createRaisedBevelBorder());

    JPanel buttonPane = new JPanel();
    buttonPane.add(rcButton);
    buttonPane.add(rrButton);
    buttonPane.add(crButton);
    */

    JScrollPane jsp = new JScrollPane();
    setLayout(new BorderLayout());
    add(label, BorderLayout.NORTH);
    //add(mySplitPane, BorderLayout.CENTER);
    jsp.setViewportView(mySplitPane);
    add(jsp,BorderLayout.CENTER);
    //add(buttonPane, BorderLayout.SOUTH);
  }

    public void updateCAInfo() {return;}
}
      







