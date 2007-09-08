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

public class NamePane extends JPanel 
implements ActionListener, RuleListener {

  private NameListener listener;
  private String myCommand;
  private int myIndex;
  private static EventQueue evtq;

  private Dimension myLabelField = new Dimension(180, 20);
  private Dimension myWholeField = new Dimension(360, 20);
  private ThreeWayCombo[] unitPanes;
  private String myTitle = null;
  private String[] myName;
  private String[] myDefault;
  private boolean myButtonOrLabel = false;
  private boolean myTwoCols = false;
  private boolean noRoom = false;
  JLabel label;
  /*
  JPanel buttonPane;
  JButton allowButton;
  JButton prohibitButton;
  JButton resetButton;
  */

  public NamePane(String[] name) {
    this(name, null, null, false, null, null, false);

  } 

  public NamePane(String[] name, String title) {
    this(name, title, null, false, null, null, false);

  } 

  public NamePane(String[] name, String title, Dimension labelField, 
		  Dimension wholeField, boolean twoCols) {
    this(name, title, null, false, labelField, wholeField, true);

  } 

  public NamePane(String[] name, boolean buttonOrLabel) {
    this(name, null, null, buttonOrLabel, null, null, false);

  } 

  public NamePane(String[] name,
		  String[] defaultValue, 
		  boolean buttonOrLabel) {
    this(name, null, defaultValue, buttonOrLabel, null, null, false);

  } 

   public NamePane(String[] name,
		  String[] defaultValue) {
    this(name, null, defaultValue, false, null, null, false);

  } 

  public NamePane(String[] name, 
		  Dimension labelField, 
		  Dimension wholeField) {
    this(name, null, null, false, labelField, wholeField, false);

  } 

  public NamePane(String[] name,
		  boolean buttonOrLabel,
		  Dimension labelField, 
		  Dimension wholeField) {

    this(name, null, null, buttonOrLabel, labelField, wholeField, false);

  } 

  public NamePane(String[] name,
		  String[] defaultValue,
		  Dimension labelField, 
		  Dimension wholeField) {
    this(name, null, defaultValue, false, labelField, wholeField, false);
  } 

  public NamePane(String[] name,
		  String[] defaultValue,
		  boolean buttonOrLabel,
		  Dimension labelField, 
		  Dimension wholeField) {
    this(name, null, defaultValue, buttonOrLabel, labelField, wholeField, false);
  }

  public NamePane(String[] name,
		  String title,
		  String[] defaultValue,
		  boolean buttonOrLabel,
		  Dimension labelField, 
		  Dimension wholeField,
		  boolean twoRow) {
    myName = name;
    if (title != null) {
      myTitle = new String(title);
    }

    //System.out.println("name length is " + name.length);
    if (defaultValue == null) {
      myDefault = new String[name.length];
      for (int i = 0; i < name.length; i++)
	myDefault[i] = null;
    } else {
      //System.out.println(" algo default is not null");
      myDefault = defaultValue;
      //System.out.println(" algo default: " +  myDefault[0]);
    }
    myButtonOrLabel = buttonOrLabel;
    if (labelField != null)
      myLabelField = labelField;
    if (wholeField != null)
      myWholeField = wholeField;
    myTwoCols = twoRow;
    noRoom = myTwoCols;
    initDisplay();
  } 

  public int length() {
    return unitPanes.length;
  }

  public void setFields(Dimension labelField, 
			Dimension wholeField) {
    if (labelField != null)
      myLabelField = labelField;
    if (wholeField != null)
      myWholeField = wholeField;

  }

  public void addNameListener(NameListener l) {
    listener = l;
  }

  public void setTitle(String title) { 
    myTitle = new String(title);
  }

  public String getTitle() { 
    return myTitle;
  }

  public String getNameCommand() {
    return myCommand;
  }

  public int getIndexCommand() {
    return myIndex;
  }

  public int getNumNames()
  {
      return unitPanes.length;
  }

  public void processEvent(AWTEvent evt) {
    if (evt instanceof NameEvent) {
      if (listener != null)
	listener.namePerformed((NameEvent) evt);
    } else {
      super.processEvent(evt);
    }
  }

  public String getCommand(int i)
  {
      return unitPanes[i].getRuleCommand();
  }

  public String getChoice(String cmd)
  {
      for (int i=0; i< unitPanes.length; i++)
      {
	  if (unitPanes[i].getRuleCommand().compareTo(cmd) == 0)
	      return unitPanes[i].getChoice();
      }
      return "";
  }

  public String getChoice(int i) {
    return unitPanes[i].getChoice();
  }
 
  public void setChoice(int i, String choice) {
    setChoice(i, choice, false);
  }
 
  public void setChoice(int i, String choice, boolean defaultValue) {
    unitPanes[i].setChoice(choice, defaultValue);
  }
  
  public void setChoice(String cmd, String choice)
  {
     for (int i=0; i< unitPanes.length; i++)
      {
	  if (unitPanes[i].getRuleCommand().compareTo(cmd) == 0)
	      unitPanes[i].setChoice(choice);
      }
  }

  public void resetPane()
  {
      int len = myDefault.length;
      //System.out.println("resetting name pane.");
      for (int i=0; i< unitPanes.length; i++)
      {
	  if (i > len)
	      unitPanes[i].setChoice(RuleEditorData.ALLOW);
	  if ((myDefault[i] == null) || 
	      (myDefault[i] == RuleEditorData.ALLOW) ||
	      ((myDefault[i] != RuleEditorData.REQUIRE) &&
	       (myDefault[i] != RuleEditorData.PROHIBIT)))
	  {
	      unitPanes[i].setChoice(RuleEditorData.ALLOW);
	      //System.out.println("set to allow # " + i +" " + myDefault[i]);
	  }
	  else
	      {
	      unitPanes[i].setChoice(myDefault[i]);
	      //System.out.println("setting " + i + " to " + myDefault[i]);
	      }
      }
  }

  public void resetChoice(int i) {
    ThreeWayCombo unitPane = unitPanes[i];
    //System.out.println(" in NP resetChoice");
    unitPane.resetChoice();
  }

  public void setEnabled(int i, boolean b)
  {
      unitPanes[i].setEnabled(b);
  }

  public void setEnabled(String cmd, boolean b)
  {
      for (int i=0; i< unitPanes.length; i++)
      {
	  if (unitPanes[i].getRuleCommand().compareTo(cmd) == 0)
	      unitPanes[i].setEnabled(b);
      }
  }

  public void setEnabled(boolean b) {
    if (label != null) {
      label.setEnabled(b);
    }
    for (int i = 0; i < myName.length; i++) {
     unitPanes[i].setEnabled(b);
    } 
    //buttonPaneSetEnabled(b);
  }

  /*
  public void buttonPaneSetEnabled( boolean b) {
    allowButton.setEnabled(b);
    prohibitButton.setEnabled(b);
    resetButton.setEnabled(b);
  }
  */

  public void enableUnit(int i) {
    unitPanes[i].setEnabled(true);
  };

  public void disableUnit(int i) {
    unitPanes[i].setEnabled(false);
  }
    

  public void print() {
    for (int i = 0; i < myName.length; i++) {
      unitPanes[i].print();
    }
    
  }

  private void initDisplay() {
    evtq = Toolkit.getDefaultToolkit().getSystemEventQueue();
    //System.out.println(" evtq initialized: " + evtq);
    enableEvents(0);
    
    JPanel labelPanel=null;

    if (!noRoom) 
    {
      if (myName.length > 1) //only add label if more than one button
      {
        if (myButtonOrLabel)
         label = new JLabel(" Select a button for more details: ");
        else
	  label = new JLabel("Please inspect values below: ");
      
        label.setFont(new java.awt.Font("Dialog", Font.BOLD, 12));
	//label.setHorizontalAlignment(SwingConstants.RIGHT);
	//label.setHorizontalAlignment(SwingConstants.LEFT);
	label.setHorizontalAlignment(SwingConstants.CENTER);
	//setAlignmentX(Component.LEFT_ALIGNMENT);
	//label.setMinimumSize(RuleEditorData.longerField);
	//label.setPreferredSize(RuleEditorData.longerField);
	//label.setBorder(BorderFactory.createRaisedBevelBorder());
	labelPanel = new JPanel();
	labelPanel.setLayout(new BoxLayout(labelPanel, BoxLayout.X_AXIS));
	labelPanel.add(label);
      }
      else
	  label = null;
    }
    
    JPanel innerPane = new JPanel();
    if (myTwoCols) {
      innerPane.setLayout (new GridLayout(0, 2));
    } else {
      innerPane.setLayout (new GridLayout(0, 1));
    }
    
    unitPanes = new ThreeWayCombo[myName.length];
    for (int i = 0; i < myName.length; i++) {
      //System.out.println(" field: " + myName[i] + "avail: " + myDefault[i]);
      unitPanes[i] = new ThreeWayCombo(myName[i],
				       myDefault[i],
				       myButtonOrLabel,
				       myLabelField, 
				       myWholeField);
      unitPanes[i].setRuleCommand(myName[i]);
      unitPanes[i].setIndexCommand(i);
      unitPanes[i].addRuleListener(this);
	
      //unitPanes[i].setBorder(BorderFactory.createRaisedBevelBorder());
      innerPane.add(unitPanes[i]);
      //add(Box.createRigidArea(new Dimension(0,10)));
    }

    if (myName.length == 1) {
      if (myDefault[0] != null && myDefault[0].equals(RuleEditorData.REQUIRE)) {
	unitPanes[0].setEnabled(false);
      }
    }
    
    //add(Box.createRigidArea(new Dimension(0,5)));
    //add(Box.createRigidArea(new Dimension(0,5)));
    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); 
    if (!noRoom) {
	if (labelPanel != null)
	    add(labelPanel);
      //label.setAlignmentX(Component.LEFT_ALIGNMENT);
    }
    add(Box.createRigidArea(new Dimension(0,10)));
    add(innerPane);
    //add(buttonPane);
    add(Box.createVerticalGlue());
    add(Box.createRigidArea(new Dimension(0,10)));
    if (myTitle == null) {
      setBorder(BorderFactory.createRaisedBevelBorder());
    } else {
      setBorder(new TitledBorder(new EtchedBorder(), myTitle));
    }
  }
  
  public void actionPerformed(java.awt.event.ActionEvent e) {
    JButton b = (JButton)e.getSource();
    if (b.getActionCommand() == RuleEditorData.ALLOW) {
      updateScreen(RuleEditorData.ALLOW);
    }
    else if (b.getActionCommand() == RuleEditorData.PROHIBIT) {
      updateScreen(RuleEditorData.PROHIBIT);
    } 
  }
  
  private void updateScreen(String choice) {
    for (int i = 0; i < myName.length; i++) {
      unitPanes[i].setChoice(choice);
    }
  }

  public void rulePerformed(RuleEvent e) {
    String command = ((ThreeWayCombo)e.getSource()).getRuleCommand();
    int    ind = ((ThreeWayCombo)e.getSource()).getIndexCommand();
    //System.out.println(" In NP rulePerformed() command: " + command + " " + ind);
  
    myCommand = command;
    myIndex = ind;
    NameEvent evt = new NameEvent(this);
    evtq.postEvent(evt);

  }
  
}
