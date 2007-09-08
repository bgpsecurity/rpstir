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

import rules.*;
import asn.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

abstract class ExtnFieldBasePane extends JPanel {

  ThreeWayCombo criticality;
  JPanel contentPane = new JPanel();
  String myName;
  String myType;
  boolean myBoarder;
  String[] myDNName;
  protected String myCriticalFlag = RuleEditorData.ALLOW;

  public ExtnFieldBasePane(String name) {
    this(name, null, null, true);   
  }

  public ExtnFieldBasePane(String name, 
			   boolean boarder) {
    this(name, null, null, false);   
  }

  public ExtnFieldBasePane(String name, String criticalFlag) {
    this(name, criticalFlag, null, true);   
  }

  public ExtnFieldBasePane(String name, String criticalFlag, String type) {
    this(name, criticalFlag, type, true);   
  }

  public ExtnFieldBasePane(String name, String criticalFlag, boolean boarder) {
    this(name, criticalFlag, null, false);   
  }

  public ExtnFieldBasePane(String name, 
			   String criticalFlag,
			   String type,
			   boolean boarder) {

    super();
    myName = name;
    myCriticalFlag = criticalFlag;
    myType = type;
    myBoarder = boarder;
    initDisplay();
    setContentPane();
  }

  abstract void setContentPane();
  abstract boolean setRule(Member m);
  abstract int createRule(Member m);

  public void setCriticality(String flag){
   //System.out.println("Setting " + flag + " for " + myName);
    myCriticalFlag = flag;
  }

  public String getCriticality() {
    myCriticalFlag = criticality.getChoice();
    return myCriticalFlag;
  }

  private void initDisplay() {
      //System.out.println("myCriticalFlag is " + myCriticalFlag);
    criticality = new ThreeWayCombo("Critical Flag: ", myCriticalFlag);
    if (myCriticalFlag == "Prohibit" || myCriticalFlag == "Require") {
      criticality.setEnabled(false);
    }
    //setContentPane();
    if (myBoarder) {
      contentPane.setBorder(new EmptyBorder(10, 10, 10, 10));
    } 
    setLayout(new BorderLayout());
    //setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); 
    //add(criticality);
    add(criticality, BorderLayout.NORTH);
    //add(criticality);
    //add(Box.createRigidArea(new Dimension(0,5)));
    add(contentPane, BorderLayout.CENTER);
    //add(contentpane);
    String name = "  " + myName + " Rule  ";
    TitledBorder border = new TitledBorder(new EtchedBorder(), name);
    //border.setTitleFont(Font.BOLD);
    setBorder(border);

  }


}
