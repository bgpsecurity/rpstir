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

public class RangeTimeData {
  private TimeData myMin;
  private TimeData myMax;
  
  public RangeTimeData(TimeData min, TimeData max) {
    myMin = min;
    myMax = max;
  }
  
  public void setMinTime(TimeData min) {
    myMin = min;
  }
  
  public void setMaxTime(TimeData max) {
    myMax = max;
  }
  
  public TimeData getMinTime() {
    return(myMin);
  }
  
  public TimeData getMaxTime() {
    return(myMax);
  }
  
  public void print(String msg) {
    //System.out.println("   " + msg + ": ");
    myMin.print("    Minimum: ");
    myMax.print("    Maximum: ");
  }	      
  
  
} // RangeTimeData
