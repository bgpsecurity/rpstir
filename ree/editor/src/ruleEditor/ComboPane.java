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

import java.awt.Toolkit;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;

public class ComboPane extends JPanel 
implements ActionListener {
  private JLabel label;
  private JComboBox comboBox;
  private String myChoice;
  private String[] myData;
  private String timeString;
  private int myDefault = 0;
  private JFrame frame;
  private NumberFormat integerFormatter;
  private final int DATE_LENGTH = 14;
  private final String DATE_FORMAT = "yyyymmddhhmmss";

  public ComboPane() {
    initDisplay(null);
  }

  public ComboPane(String[] data) {
    myChoice = data[0];
    myData = data;
    initDisplay(myData);
  }

  public ComboPane(String[] data, int defaultData) {
    myDefault = defaultData;
    myChoice = data[myDefault];
    initDisplay(data);
  }
    
  public void setEnabled(boolean b) {
    if (myData == null){
      label.setEnabled(b);
    }
    comboBox.setEnabled(b);
  } 

  public String getChoice() {
    myChoice = (String)comboBox.getSelectedItem();
    return myChoice;
  }

  public String getTime() { 
    myChoice = (String)comboBox.getSelectedItem();
    return myChoice;
  }

  public void setTime(String time) { 
    myChoice = time;
    comboBox.setSelectedItem(time);
  }

  public void print() {
    if (myData != null) {
      //System.out.print(myChoice);
    }
    else {
      //System.out.println("   The time is : " + myChoice);
    }
  }

  private void initDisplay(String[] data) {
    integerFormatter = NumberFormat.getNumberInstance(Locale.US);
    integerFormatter.setParseIntegerOnly(true);

    if (data != null) {
      comboBox = new JComboBox(data);
      comboBox.setSelectedIndex(myDefault);
    }
    else { // *** Need to work on Fix Time Format
      label = new JLabel("Enter time in GMT formatted as [" +
			 DATE_FORMAT + "] :");
      comboBox = new JComboBox();
      comboBox.addItem("");
      comboBox.setEditable(true);
      add(label);
    }
    comboBox.setBackground(Color.white);
    comboBox.addActionListener(this);
    add(comboBox);
  }

  private boolean checkDates(String msg, char[] data, int num, int low, int high) {
    boolean error = false;

    for (int i = 0; i < data.length; i++) {
      if (!Character.isDigit(data[i])) {
	error = true;
	JOptionPane.showMessageDialog(frame, "Digit is required.");
      }
    }

    if (!error) {
      if (low != 0 && high !=0) {
	if (num < low || num > high) {
	  error = true;
	  JOptionPane.showMessageDialog(frame, "Date (" + msg + ") is not witnin the range.");
	}
      }
      else if (low != 0 && high == 0) {
	if (num < low) {
	  error = true;
	  JOptionPane.showMessageDialog(frame, "Date (" + msg + ") is not witnin the range.");
	}
      }
      else if (low == 0 && high != 0) {
	if (num > num) {
	  error = true;
	  JOptionPane.showMessageDialog(frame, "Date (" + msg + ") is not witnin the range.");
	}
      }
    }

    return error;
	
  }
  
  public boolean checkDate()
  {
     myChoice = (String)comboBox.getSelectedItem();
     return checkDate(myChoice);
  }

  private boolean checkDate(String date) {
    boolean error = false;
    String yearS, monthS, dayS, hourS, minuteS, secondS;
    char[] data = null;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

    System.out.println("in combopane check date");
    for (int i = 0; i < (date.length()-1); i++) {
      if (!Character.isDigit(date.charAt(i))) {
	error = true;
	JOptionPane.showMessageDialog(frame, "Digit is required.");
	break;
      } 
    }
    if (date.length() != DATE_LENGTH)
    {
	JOptionPane.showMessageDialog(null, 
				      "The fixed date format requires " +
				      DATE_LENGTH +
				      " characters.\nPlease try again.",
				      "Error in Fixed Date field.",
				      JOptionPane.ERROR_MESSAGE);
	error = true;
    }
    if (!error) {
	yearS = date.substring(0, 4);
	//yearS[yearS.length()] = '\n';
	monthS = date.substring(4, 6);
	dayS = date.substring(6, 8);
	hourS = date.substring(8, 10);
	minuteS = date.substring(10, 12);
	secondS = date.substring(12, 14);

	//year = integerFormatter.parse(yearS).intValue();
	year = Integer.parseInt(yearS);
	error = checkDates("year", yearS.toCharArray(), year, 2000, 0);
	month = Integer.parseInt(monthS);
	error = checkDates("month", monthS.toCharArray(), month, 1, 12);
	day = Integer.parseInt(dayS);
	error = checkDates("day", dayS.toCharArray(), day, 1, 31);
	hour = Integer.parseInt(hourS);
	error = checkDates("hour", hourS.toCharArray(), hour, 0, 23);
	minute = Integer.parseInt(minuteS);
	error = checkDates("minute", minuteS.toCharArray(), minute, 0, 59);
	second = Integer.parseInt(secondS);
	error = checkDates("second", secondS.toCharArray(), second, 0, 59);
      
      if (error) {
	myChoice = null;
	// Reset to original
	comboBox.setSelectedItem("");
	repaint();      
      } 
      
    }

    return error;
  }

  
  public void actionPerformed(java.awt.event.ActionEvent e) {
      /*
    JComboBox cb = (JComboBox)e.getSource();
    //myChoice = cb.getSelectedIndex();
    myChoice = (String)cb.getSelectedItem(); 
    //myChoice = myChoice + "Z";
    if (myData == null) {
      if (myChoice == DATE_FORMAT) {
	// do nothing
      }
      if (myChoice.length() != DATE_LENGTH) {
	// error msg
	JOptionPane.showMessageDialog(frame, "The date format requires " +
				      DATE_LENGTH +
				      " characters.\nPlease try again.");
	myChoice = null;
      } else {
	// Check the fix time format 
	checkDate(myChoice); // currently screen on TimePane
      }
    }
      */
  }
  
} //ComboPane







