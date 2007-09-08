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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class NextUpdatePane extends FieldBasePane 
implements ActionListener {
  JRadioButton fixOButton = new JRadioButton("Fixed offset from thisUpdate time:");
  JRadioButton rangeButton = new JRadioButton("Range offset from thisUpdate time:");
  TimeLthUnit fixOTimeLthUnit = new TimeLthUnit();
  TimeLthUnit rangeTimeMinLthUnit = new TimeLthUnit();
  TimeLthUnit rangeTimeMaxLthUnit = new TimeLthUnit();
  JLabel minLabel;
  JLabel maxLabel;
  private JFrame frame;

  private String myRadioChoice = "FO";
  private Object mySrc;

  public NextUpdatePane() {
    initDisplay();
  }
  
  public int createRule(Member m) {
    boolean naMonthUnit= false;
    int naTimeLth = 0;
    boolean naMinMonthUnit = false;
    int naMinLth = 0;
    boolean naMaxMonthUnit = false;
    int naMaxLth = 0;
    int numUnit;
    String unit;
    String timeStr;
    AsnGeneralizedTime genTime = new AsnGeneralizedTime();
    DateRule d;
    TimeUnit timeUnit;
    TimeUnit minTimeUnit;
    TimeUnit maxTimeUnit;

    if (myRadioChoice.equals("FO")) {

       timeUnit = TimeUnit.getTimeLth(getNAFOTime().getLth(), 
			     getNAFOTime().getUnit());
       naTimeLth = timeUnit.getUnitLth();
       naMonthUnit = timeUnit.getMonthBool();  
       //System.out.println(" NextAfterPane.  Fix time: " + naTimeLth);
       if (naTimeLth == 0) {
	 JOptionPane.showMessageDialog(frame,
				       "Please fix \"NextUpdate\".  Its value should not be 0."); 
	 return RuleEditorData.FAILED;
       }
    }
    else if (myRadioChoice.equals("RO")) {
      minTimeUnit = TimeUnit.getTimeLth(getNAROTime().getMinTime().getLth(), 
			    getNAROTime().getMinTime().getUnit());
      naMinLth = minTimeUnit.getUnitLth();
      naMinMonthUnit = minTimeUnit.getMonthBool(); 
      maxTimeUnit = TimeUnit.getTimeLth(getNAROTime().getMaxTime().getLth(), 
			    getNAROTime().getMaxTime().getUnit()); 
      naMaxLth = maxTimeUnit.getUnitLth();
      naMaxMonthUnit = maxTimeUnit.getMonthBool(); 
      if (minTimeUnit.greaterThan(maxTimeUnit)) {
	JOptionPane.showMessageDialog(frame,
				      "Please fix \"NextUpdate\".  Maximum value is not greater than minimum value."); 
	return RuleEditorData.FAILED;
      }
    }

    m.name.write("Next Update");
    m.tagtype.write(AsnStatic.ASN_UTCTIME); //0x17
    m.rule.add();
    d = (DateRule)m.rule.ref.date;// DateRule 
    if (myRadioChoice == "FO") {
      d.min.write(naTimeLth); 
      d.max.write(naTimeLth);
      if (naMonthUnit) {
	d.momin.write(AsnStatic.ASN_BOOL_TRUE);
	d.momax.write(AsnStatic.ASN_BOOL_TRUE);
      }
      d.ref.write("-"); // Reference to notBefore
    }
    else if (myRadioChoice == "RO") {
      d.min.write(naMinLth);
      d.max.write(naMaxLth);
      if (naMinMonthUnit) {
	d.momin.write(AsnStatic.ASN_BOOL_TRUE);
      }
      if (naMaxMonthUnit) {
	d.momax.write(AsnStatic.ASN_BOOL_TRUE);
      }
      d.ref.write("-"); // Reference to notBefore
    }

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
    int lth;
    String unit;
    TimeUnit tu;
    boolean mon = false;
    AsnGeneralizedTime genTime = new AsnGeneralizedTime();
    AsnByteArray time;
    AsnIntRef i = new AsnIntRef();
    AsnIntRef l = new AsnIntRef();
    AsnIntRef h = new AsnIntRef();

    if (m != null && m.rule != null && m.rule.ref != null &&
      m.rule.ref.date != null)
      {
      DateRule d = (DateRule)m.rule.ref.date;// DateRule 
      d.min.read(l);
      d.max.read(h);
      if (l.val == h.val) 
        { // FO
        if (d.momax != null) mon = true; // unit is month
        tu = new TimeUnit(h.val, mon);
        lth = tu.getDisplayTime();
        unit = tu.getDisplayTimeUnit();
        //System.out.println(" Not after time (FO): " + lth + " " + unit);
        fixOButton.setSelected(true);
        fixOTimeLthUnit.setEnabled(true);
        fixOTimeLthUnit.setTime(lth, unit);
        rangeTimeMinLthUnit.setEnabled(false);
        rangeTimeMaxLthUnit.setEnabled(false);
        myRadioChoice = "FO";
        } 
      else 
        { // RO
        rangeButton.setSelected(true);
        fixOTimeLthUnit.setEnabled(false);
        rangeTimeMinLthUnit.setEnabled(true);
        rangeTimeMaxLthUnit.setEnabled(true);
        minLabel.setEnabled(true);
        maxLabel.setEnabled(true);

        if (d.momin != null) mon = true; // unit is month
        tu = new TimeUnit(l.val, mon);
        lth = tu.getDisplayTime();
        unit = tu.getDisplayTimeUnit();
        //System.out.println(" Not after time (RO, low): " + lth + " " + unit);
        rangeTimeMinLthUnit.setTime(lth, unit);
        if (d.momax != null) mon = true; // unit is month
        tu = new TimeUnit(h.val, mon);
        lth = tu.getDisplayTime();
        unit = tu.getDisplayTimeUnit();
        //System.out.println(" Not after time (RO, high): " + lth + " " + unit);
        rangeTimeMaxLthUnit.setTime(lth, unit);
        myRadioChoice = "RO";
        }
      }
    return true;
    }

  public void actionPerformed(java.awt.event.ActionEvent e) {
    myRadioChoice = e.getActionCommand();
    Object mySrc = e.getSource();
    
    //System.out.println(" radio choice: " + myRadioChoice);
     if (mySrc == fixOButton) {
      fixOTimeLthUnit.setEnabled(true);
      rangeTimeMinLthUnit.setEnabled(false);
      rangeTimeMaxLthUnit.setEnabled(false);
      minLabel.setEnabled(false);
      maxLabel.setEnabled(false);
    }
    else if (mySrc == rangeButton) {
      fixOTimeLthUnit.setEnabled(false);
      rangeTimeMinLthUnit.setEnabled(true);
      rangeTimeMaxLthUnit.setEnabled(true);
      minLabel.setEnabled(true);
      maxLabel.setEnabled(true);
      
    }

  } 

  public String getNAChoice() {
    return myRadioChoice;
  }
  
  public Object getNAObject() {
    return mySrc;
  }
  
  public TimeData getNAFOTime() {
    return (fixOTimeLthUnit.getTime());  
  }
  
  public RangeTimeData getNAROTime() {
    RangeTimeData rangeData = 
      new RangeTimeData(rangeTimeMinLthUnit.getTime(), 
			rangeTimeMaxLthUnit.getTime());
    
    return(rangeData);
  }
  

  private void initDisplay() {
    //NAPane.setLayout(gridBagLayout1);
    setBorder(new TitledBorder(new EtchedBorder(), "  Next Update  "));

    JPanel pane = new JPanel();
    pane.setLayout(new GridLayout(5, 2, 5, 5));
    
    fixOButton.setActionCommand("FO");
    rangeButton.setActionCommand("RO");
    fixOButton.setSelected(true);
    
    fixOButton.addActionListener(this);
    rangeButton.addActionListener(this);
    ButtonGroup NAGroup = new ButtonGroup();
    NAGroup.add(fixOButton);
    NAGroup.add(rangeButton);
    
    minLabel = new JLabel("      Minimun value:");
    maxLabel = new JLabel("      Maximum value:");
    
    fixOTimeLthUnit.setEnabled(true);
    fixOTimeLthUnit.setTime(0,RuleEditorData.MONTHS);
    rangeTimeMinLthUnit.setEnabled(false);
    rangeTimeMinLthUnit.setTime(0,RuleEditorData.MONTHS);
    rangeTimeMaxLthUnit.setEnabled(false);
    rangeTimeMaxLthUnit.setTime(0,RuleEditorData.MONTHS);
    minLabel.setEnabled(false);
    maxLabel.setEnabled(false);
    //NAPane.add(new JTextField());
    pane.add(fixOButton);
    pane.add(fixOTimeLthUnit);
    pane.add(rangeButton);
    pane.add(new JLabel());
    pane.add(minLabel);
    pane.add(rangeTimeMinLthUnit);
    pane.add(maxLabel);
    pane.add(rangeTimeMaxLthUnit);

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    add(Box.createRigidArea(new Dimension(0,5)));
    add(pane);
    add(Box.createVerticalGlue());

        
  } 

  public void resetPane()
  {
      fixOTimeLthUnit.setTime(0,RuleEditorData.MONTHS);
      rangeTimeMinLthUnit.setTime(0,RuleEditorData.MONTHS);
      rangeTimeMaxLthUnit.setTime(0,RuleEditorData.MONTHS);
  }

}
