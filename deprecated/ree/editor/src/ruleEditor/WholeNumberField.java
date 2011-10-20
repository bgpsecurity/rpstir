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

import javax.swing.*; 
import javax.swing.text.*; 

import java.awt.Toolkit;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;

public class WholeNumberField extends JTextField {
  private Toolkit toolkit;
  private NumberFormat integerFormatter;
  private JFrame frame;

  public WholeNumberField(int value) {
    toolkit = Toolkit.getDefaultToolkit();
    integerFormatter = NumberFormat.getNumberInstance(Locale.US);
    integerFormatter.setParseIntegerOnly(true);
    setValue(value);
  }
  
  public void setEnabled(boolean b) {
    super.setEnabled(b);
  }
  
  public int getValue() {
    int retVal = 0;
    String txt = getText().trim();
    //System.out.println("WholeNumber. txt: " + txt);
    try {
	retVal = Integer.valueOf(txt).intValue();
	if (retVal < 0)
	    retVal = 0 - retVal;
	//retVal = integerFormatter.parse(txt).intValue();
    } catch (Exception e) {
      System.out.println("WholeNumberField bad number");
    }
    return retVal;
  }
  
  public void setValue(int value) {
      if (value < 0)
	  value = 0 - value;
      setText(String.valueOf(value).toString());
      //setText(integerFormatter.format(value));
  }
  
}
