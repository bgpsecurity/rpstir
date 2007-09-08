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

public class TimeData {
  private int myLth;
  private String myUnit;
  
  public TimeData(int lth, String unit) {
    myLth = lth;
    myUnit = unit;
  }
  
  public void setLth(int lth) {
    myLth = lth;
  }
  
  public void setUnit(String unit) {
    myUnit = unit;
  }
  
  public int getLth(){
    return myLth;
  }
  
  public String getUnit() {
    return myUnit;
  }
  
  public void print(String msg) {
    //System.out.println("     " + msg + myLth + " " + myUnit);
  }
  
} // TimeData


