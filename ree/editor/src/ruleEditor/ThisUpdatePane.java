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
import rules.*;
import asn.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class ThisUpdatePane extends FieldBasePane 
implements  ActionListener {
  private JFrame frame;
  final static int BIG = 500000;

  String[] timeUnits = {
      RuleEditorData.MINUTES,
      RuleEditorData.HOURS,
      RuleEditorData.DAYS,
      RuleEditorData.WEEKS,
      RuleEditorData.MONTHS
  };
    
  TimeLthUnit NBLthUnit = new TimeLthUnit(timeUnits);

  public ThisUpdatePane() {
      initDisplay();
      NBLthUnit.setTime(0,RuleEditorData.HOURS);
  }

  public TimeData getTUTime() {
    return (NBLthUnit.getTime());  
  }

  public void resetPane()
  {
      NBLthUnit.setTime(0,RuleEditorData.HOURS);
  }

  public void actionPerformed(java.awt.event.ActionEvent e) {

  }
  
  public int createRule(Member m) {
    int numUnit = getTUTime().getLth();
    String unit = getTUTime().getUnit();
    //System.out.println(" thisUpdate: " + numUnit + " " + unit);
    TimeUnit timeUnit = TimeUnit.getTimeLth(numUnit, unit);
    int timeLth = timeUnit.getUnitLth();
    boolean monthUnit = timeUnit.getMonthBool();
    if (timeLth == 0) {
      JOptionPane.showMessageDialog(frame,
				    "Please fix \"ThisUpdate\".  Its value should not be 0."); 
      return RuleEditorData.FAILED;

    }

    m.name.write("This Update");
    m.tagtype.write(AsnStatic.ASN_UTCTIME); //0x30
    m.rule.add();
    DateRule d = (DateRule)m.rule.ref.date;// DateRule 
    d.max.write(0); 
    d.min.write(0-timeLth);
    if (monthUnit) {
      d.momin.write(AsnStatic.ASN_BOOL_TRUE);
      //d.momax.write(AsnStatic.ASN_BOOL_TRUE);
    }
    //System.out.println(" thisUpdate: " + timeLth + " " + monthUnit);
    d.ref.write(""); // Reference to current

    return RuleEditorData.SUCCESS;

  }

  public boolean setRule(Member m) {
    AsnIntRef t = new AsnIntRef();
    AsnIntRef b = new AsnIntRef();
    boolean mon = false;
    TimeUnit tu;

    if (m == null || m.rule == null || m.rule.ref == null ||
      m.rule.ref.date == null) return true;
    DateRule d = (DateRule)m.rule.ref.date;// DateRule 
    d.min.read(t);
    d.momin.read(b);
    if (b.val != 0) mon = true; // unit is month

    //System.out.println(" This update: " + t.val + " " + Integer.toHexString(t.val) + " " + 
    //  (t.val & 0xFFFF) + " " + (0xFFFF + 1 - (t.val & 0xFFFF)) + " month: " + mon);
    tu = new TimeUnit((-t.val), mon);
    int lth = tu.getDisplayTime();
    String unit = tu.getDisplayTimeUnit();
    //System.out.println(" thisUpdate time: " + lth + " " + unit);
    NBLthUnit.setTime(lth, unit);
    return true;
  }

  private void initDisplay() {
    setBorder(new TitledBorder(new EtchedBorder(), "  This Update  "));
    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

    JPanel NBPane = new JPanel();
    //NBPane.setLayout(new GridLayout(1, 2));
    JLabel laterLabel= new JLabel("  Before current time by as much as: ");
    //NBLthUnit.setVerticalAlignment(SwingConstants.CENTER);
    //laterLabel.setBorder(BorderFactory.createRaisedBevelBorder());
    //NBLthUnit.setBorder(BorderFactory.createRaisedBevelBorder());
    //NBLthUnit.setAlignmentX(Component.CENTER_ALIGNMENT);
    //NBLthUnit.setPreferredSize(new Dimension(300, 40));
    //NBLthUnit.setMinimumSize(new Dimension(300, 40));
    //NBLthUnit.setMaximumSize(new Dimension(300, 40));
    NBPane.setLayout(new BoxLayout(NBPane, BoxLayout.X_AXIS));
    NBPane.add(laterLabel);
    NBPane.add(Box.createRigidArea(new Dimension(10,0)));
    NBPane.add(NBLthUnit);
    NBPane.add(Box.createRigidArea(new Dimension(10,0)));
    NBPane.setPreferredSize(new Dimension(500, 50));
    NBPane.setMinimumSize(new Dimension(500, 50));
    NBPane.setMaximumSize(new Dimension(500, 50));

    add(Box.createRigidArea(new Dimension(0, 10)));
    add(NBPane);
    add(Box.createVerticalGlue());


  }

}
