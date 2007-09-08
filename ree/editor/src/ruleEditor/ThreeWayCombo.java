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

public class ThreeWayCombo extends JPanel 
  implements ActionListener {

  private RuleListener listener;
  private String myCommand;
  private int myIndex;
  private static EventQueue evtq;
  private static boolean flag = true;

  private JLabel label = null;
  private JButton button = null;
  private Object o;
  private JComboBox threeWayBox;
  private JTextArea buffer = new JTextArea();
  private String myLabel = null;
  //private Dimension myLabelField = null;
  //private Dimension myWholeField = null;  
  private Dimension myLabelField = new Dimension(140, 20);
  private Dimension myWholeField = new Dimension(250, 20);
  private String myChoice = null;
  private String oldChoice = null;
  private static final String theChoice = RuleEditorData.ALLOW;
  private int threeWay = RuleEditorData.THREE_WAY;
  private boolean myButtonOrLabel = false; //Label

  public ThreeWayCombo(String name) {
    this(name, RuleEditorData.ALLOW, -1, false, null, null); 
  }

  public ThreeWayCombo(String name, boolean buttonOrLabel) {
    this(name, RuleEditorData.ALLOW, -1, buttonOrLabel, null, null); 
  }


  public ThreeWayCombo(String name, String choice, int way) {
    this(name, choice, way, false, null, null); 

  }

  public ThreeWayCombo(String name, String choice) {
    this(name, choice, -1, false, null, null); 
  }

  public ThreeWayCombo(String name, int way, String choice) {
    this(name, choice, way, false, null, null); 
  }

  public ThreeWayCombo(String name, 
		       Dimension labelField, 
		       Dimension wholeField) {
    this(name, RuleEditorData.ALLOW, -1, false, labelField, wholeField); 
  }

  public ThreeWayCombo(String name,
		       boolean buttonOrLabel,
		       Dimension labelField, 
		       Dimension wholeField) {
    this(name, RuleEditorData.ALLOW, -1, buttonOrLabel, labelField, wholeField); 
  }

  public ThreeWayCombo(String name, 
		       int way,
		       Dimension labelField, 
		       Dimension wholeField) {
    this(name, RuleEditorData.ALLOW, way, false, labelField, wholeField); 
  }

  public ThreeWayCombo(String name,
		       String choice,
		       Dimension labelField, 
		       Dimension wholeField) {
    this(name, choice, -1, false, labelField, wholeField); 
  }

  public ThreeWayCombo(String name,
		       String choice,
		       int way,
		       Dimension labelField, 
		       Dimension wholeField) {

    this(name, choice, way, false, labelField, wholeField); 
  }

  public ThreeWayCombo(String name,
		       String choice,
		       boolean buttonOrLabel,
		       Dimension labelField, 
		       Dimension wholeField) {

    this(name, choice, -1, buttonOrLabel, labelField, wholeField); 
  }

  public ThreeWayCombo(String name,
		       String choice,
		       int way,
		       boolean buttonOrLabel,
		       Dimension labelField, 
		       Dimension wholeField) {
    myLabel = name;
    if (choice  != null) {
      myChoice = choice;
    }
    else {
      myChoice = theChoice;
    }
    if (way == -1) {
      threeWay = RuleEditorData.THREE_WAY;
    } else {
      threeWay = way;
    }
    myButtonOrLabel = buttonOrLabel;
    if (labelField != null) {
      myLabelField = labelField;
    }
    if (wholeField != null) {
      myWholeField = wholeField;
    }

    initDisplay();
  }

  public void addRuleListener(RuleListener r) {
    listener = r;
  }

  public void setRuleCommand(String command) {
    myCommand = command;
  }

  public String getRuleCommand() {
    return myCommand;
  }

  public void setIndexCommand(int ind) {
    myIndex = ind;
  }

  public int getIndexCommand() {
    return myIndex;
  }

  public void processEvent(AWTEvent evt) {
    if (evt instanceof RuleEvent) {
      if (listener != null)
	listener.rulePerformed((RuleEvent) evt);
    } else {
      super.processEvent(evt);
    }
  }

  public void setField(Dimension labelField, 
		       Dimension wholeField) {
    if (labelField != null) {
      myLabelField = labelField;
      }
    if (wholeField != null) {
      myWholeField = wholeField;
    }
  }

  public String getChoice() {
    return myChoice;
  }

  public void setChoice(String choice) {
    myChoice = choice;
    threeWayBox.setSelectedItem(myChoice);
  }

  public void setChoice(String choice, boolean enableValue) {
    myChoice = choice;
    threeWayBox.setSelectedItem(myChoice);
    if (myChoice.equals(RuleEditorData.REQUIRE) && enableValue) {
      setEnabled(false);
    }
  }

  public void resetChoice() {
    //System.out.println("**** in resetChoice() oldChoice: " + oldChoice + "  myChoice: " + myChoice);
    myChoice = oldChoice;
    flag = false;
    threeWayBox.setSelectedItem(myChoice);
  }

  public void setEnabled(boolean b) {
    //if (label != null) {
    //  label.setEnabled(b);
    //}
    //else {
    //  button.setEnabled(b);
    //}
    threeWayBox.setEnabled(b);
    buffer.setEnabled(b);
  }

  public void print() {
    //System.out.println(" " + myLabel + " " + myChoice);
  }
      
  private void initDisplay() {

    evtq = Toolkit.getDefaultToolkit().getSystemEventQueue();
    //System.out.println(" evtq initialized: " + evtq);
    enableEvents(0);

    String[] ways;

    if (threeWay == RuleEditorData.THREE_WAY) {
      ways = new String[3];
      ways[0] = RuleEditorData.PROHIBIT;
      ways[1] = RuleEditorData.ALLOW;
      ways[2] = RuleEditorData.REQUIRE;
    }
    else if (threeWay == RuleEditorData.THREE_WAY) {
      ways = new String[2];
      ways[0] = RuleEditorData.PROHIBIT;
      ways[1] = RuleEditorData.ALLOW;
    }
    else {
      ways = new String[2];
      ways[0] = "No";
      ways[1] = "Yes";
    }
    if (myButtonOrLabel) {
      button = new JButton(myLabel);
      button.setActionCommand(myLabel);
      button.addActionListener(this);
      button.setMinimumSize(myLabelField);
      button.setPreferredSize(myLabelField);
      //button.setMaximumSize(myLabelField);
      //button.setHorizontalAlignment(SwingConstants.RIGHT);
      //button.setBorder(BorderFactory.createRaisedBevelBorder());
      o = (JButton)button;
    }
    else {
      label = new JLabel(myLabel);
      label.setMinimumSize(myLabelField);
      label.setPreferredSize(myLabelField);
      //label.setMaximumSize(myLabelField);
      //label.setHorizontalAlignment(SwingConstants.RIGHT);
      //label.setBorder(BorderFactory.createRaisedBevelBorder());
      o = (JLabel)label;
    }
    threeWayBox = new JComboBox(ways);
    threeWayBox.setSelectedItem(myChoice);
    //Font f = threeWayBox.getFont();;
    //System.out.println("ThreeWay font: " + f);
    if (myChoice.equals(RuleEditorData.REQUIRE)) {
      setEnabled(false);
    }
    Dimension dim = new Dimension(90, 20);
    threeWayBox.setMinimumSize(dim);
    threeWayBox.setPreferredSize(dim);
    threeWayBox.setMaximumSize(dim);
    //threeWayBox.setBorder(BorderFactory.createRaisedBevelBorder());
    threeWayBox.addActionListener(this);

    setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
    add(Box.createHorizontalGlue());
    if (myButtonOrLabel) {
      add(button);
    }
    else {
      add(label);
    }
    add(Box.createRigidArea(new Dimension(1, 0))); // 5 x 0
    add(threeWayBox);
    add(Box.createRigidArea(new Dimension(1, 0)));
    add(buffer);
    buffer.setEnabled(false);
    //buffer.setBackground(Color.red);
    updateScreen(myChoice);
    buffer.setPreferredSize(new Dimension(10, 15)); // 15 x 15
    buffer.setMaximumSize(new Dimension(10, 15));
    buffer.setMinimumSize(new Dimension(10, 15));
    add(Box.createHorizontalGlue());
    setMinimumSize(myWholeField);
    setPreferredSize(myWholeField);
    setAlignmentX(LEFT_ALIGNMENT);
  }

  public void actionPerformed(java.awt.event.ActionEvent e) {
    Object o = e.getSource();
    if (o instanceof JComboBox) {
      JComboBox cb = (JComboBox)o;
      String choice = (String)cb.getSelectedItem();
      //System.out.println(" In ThreeWayCombo actionPerformed(): " + choice);
      oldChoice = myChoice;
      myChoice = choice;
      updateScreen(choice);
    }
    else if (o instanceof JButton) {
      //System.out.println(" Button pressed: " + button.getText());
      updateScreen(null);
    }
  }

  private void resetScreen(String choice) {
    if (choice == RuleEditorData.ALLOW) {
      buffer.setBackground(Color.yellow);
    }
    else if (choice == RuleEditorData.REQUIRE || choice == "Yes") {
      buffer.setBackground(Color.green);
    }
    else if (choice == RuleEditorData.PROHIBIT || choice == "No") {
      buffer.setBackground(Color.red);
    }
    //System.out.println("**** in resetScreen(): " + choice);
    repaint();
  }

  private void updateScreen(String choice) {
    //System.out.println("**** in updateScreen()");

    if (choice != null)
      resetScreen(choice);
    RuleEvent e = new RuleEvent(this);
    //System.out.println(" flag: " + flag);
    //System.out.println(" RuleEvent: " + e);
    if (flag) {
      evtq.postEvent(e);
    }
    else {
      flag = true;
    }
  }

} 
