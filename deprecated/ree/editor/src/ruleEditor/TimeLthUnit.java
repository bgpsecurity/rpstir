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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.text.*; 

import java.text.*; 

public class TimeLthUnit extends JPanel 
implements  ActionListener {
  private String[] myTimeUnits;
  private String myChoice = "years";
  //private int myTime;
  private int numPeriods;
  TimeData myTime;
  //Create the text fields and set them up.
  //MyDocumentListener myDocumentListener = new MyDocumentListener();
  
  ComboPane timeUnit;
  //JTextField timeLth = new JTextField();
  private WholeNumberField numPeriodsField;
  
  String[] timeUnits = {
    RuleEditorData.YEARS,
    RuleEditorData.MONTHS,
    RuleEditorData.WEEKS,
    RuleEditorData.DAYS,
    RuleEditorData.HOURS,
    RuleEditorData.MINUTES
  };
  
  public TimeLthUnit(String[] units) {
    myTimeUnits = units;
    initDisplay();
  }

  public TimeLthUnit() {
    myTimeUnits = timeUnits;
    initDisplay();
  }
  
  public TimeData getTime() {
    myChoice = timeUnit.getChoice();
    numPeriods = numPeriodsField.getValue();
    myTime = new TimeData(numPeriods, myChoice);
    return myTime;
  }

  public void setTime(int time, String choice) {
    myChoice = choice;
    numPeriods = time;
    timeUnit.setTime(choice);
    numPeriodsField.setValue(time);     //set data
  }
  
  public void setEnabled(boolean b) {
    timeUnit.setEnabled(b);
    numPeriodsField.setEnabled(b);
  }
  
  public void print(String msg) {
    getTime().print(msg);
  }
  
  
  private void initDisplay() {
    timeUnit  = new ComboPane(myTimeUnits);
    numPeriodsField = new WholeNumberField(numPeriods);
    //numPeriodsField.getDocument().addDocumentListener(myDocumentListener);
    //numPeriodsField.getDocument().addDocumentListener(this);
    //numPeriodsField.getDocument().putProperty("name", "numPeriods");
    
    numPeriodsField.setPreferredSize(RuleEditorData.shortField);
    //numPeriodsField.addActionListener(this);
    add(numPeriodsField);
    add(timeUnit);
  }
  
  public void actionPerformed(ActionEvent evt) {
    //String text = textField.getText();
    //textArea.append(text + newline);
    //textField.selectAll();
  }
  
  //class MyDocumentListener implements DocumentListener {
    /*
    public void insertUpdate(DocumentEvent e) {
      calculateValue(e);
    }
    public void removeUpdate(DocumentEvent e) {
      calculateValue(e);
    }
    public void changedUpdate(DocumentEvent e) {
      // we won't ever get this with PlainDocument
    }
    private void calculateValue(DocumentEvent e) {
      Document whatsup = e.getDocument();
      if (whatsup.getProperty("name").equals("numPeriods"))
	numPeriods = numPeriodsField.getValue();
    }
    */
  //}
} //TimeLthUnit

