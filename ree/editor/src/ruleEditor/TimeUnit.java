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

public class TimeUnit {
  int myLth;
  String myUnit;
  boolean myMonthUnit;
    
  public TimeUnit(int lth, boolean monthUnit) {
    myLth = lth;
    myMonthUnit = monthUnit;
  }
  public TimeUnit(int lth, String unit, boolean monthUnit) {
    myLth = lth;
    myUnit = unit;
    myMonthUnit = monthUnit;
  }

    
  protected int getUnitLth() {
    return myLth;
  }
    
  protected boolean getMonthBool() {
    return myMonthUnit;
  }

  public static TimeUnit getTimeLth(int numUnit, String unit) {
    int timeLth = 0;
    boolean monthUnit = false;

    if (unit.equals(RuleEditorData.YEARS)) {
      monthUnit = true;
      timeLth = numUnit * 12;
    } else if (unit.equals(RuleEditorData.MONTHS)) {
      monthUnit = true;
      timeLth = numUnit;
    } else if (unit.equals(RuleEditorData.WEEKS)) {
      timeLth = numUnit * 7 * 24 * 60 * 60;
    } else if (unit.equals(RuleEditorData.DAYS)) {
      timeLth = numUnit * 24 * 60 * 60;
    } else if (unit.equals(RuleEditorData.HOURS)) {
      timeLth = numUnit * 60 * 60;
    } else if (unit.equals(RuleEditorData.MINUTES)) {
      timeLth = numUnit * 60;
    }

    TimeUnit timeUnit = new TimeUnit(timeLth, unit, monthUnit);

    return timeUnit;

  }

  public int getDisplayTime() {
    int lth = 0, tlth = (myLth >= 0)? myLth: -myLth;
    
    if (myMonthUnit) { // unit is month or year
      if ((tlth % 12) == 0) { // unit is year
	lth = tlth / 12;
	myUnit = new String(RuleEditorData.YEARS);
      } else { 
	lth = tlth;
	myUnit = new String(RuleEditorData.MONTHS);
      }
    } else { // unit is seconds
      if ((tlth % (60 * 60 * 24 * 7)) == 0) {
	lth = tlth / (60 * 60 * 24 * 7);
	myUnit = new String(RuleEditorData.WEEKS);
      } else if ((tlth % (60 * 60 * 24)) == 0) {
	lth = tlth / (60 * 60 * 24);
	myUnit = new String(RuleEditorData.DAYS);
      } else if ((tlth % (60 * 60)) == 0) {
	lth = tlth / (60 * 60);
	myUnit = new String(RuleEditorData.HOURS);
      } else {
	lth = tlth / (60);
	myUnit = new String(RuleEditorData.MINUTES);
      }
    }
    //System.out.println(" Display time: " + lth + " " + myUnit);
    return lth;
  }

  public String getDisplayTimeUnit() {
    return myUnit;
  }


  public boolean greaterThan(TimeUnit b) {
    int numA, numB;
    if (myMonthUnit == b.myMonthUnit) {
      return (myLth > b.myLth);
    }
    else {
      if (myMonthUnit) {
	numA = myLth * 30 * 24 * 60 * 60;
	numB = b.myLth;
      }
      else {
	numB = b.myLth * 30 * 24 * 60 * 60;
	numA = myLth;
      }
      return (numA > numB);
    }
  }

}
