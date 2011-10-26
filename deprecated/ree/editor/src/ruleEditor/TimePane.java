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

public class TimePane extends FieldBasePane 
implements  ActionListener {
  //TimeLthUnit laterTimeLthUnit = new TimeLthUnit();
  TimeLthUnit NBALthUnit = new TimeLthUnit();
  TimeLthUnit NBBLthUnit = new TimeLthUnit();
  JRadioButton fixTButton = new JRadioButton("Fixed time:");
  JRadioButton fixOButton = new JRadioButton("Fixed offset from notBefore:");
  JRadioButton rangeButton = new JRadioButton("Range offset from notBefore:");
  ComboPane fixTimePane = new ComboPane();
  TimeLthUnit fixOTimeLthUnit = new TimeLthUnit();
  TimeLthUnit rangeTimeMinLthUnit = new TimeLthUnit();
  TimeLthUnit rangeTimeMaxLthUnit = new TimeLthUnit();
  JLabel minLabel;
  JLabel maxLabel;
  TimeUnit maxTimeUnit;
  TimeUnit minTimeUnit;
  
  private String myRadioChoice = "FO";
  private Object mySrc;
  private JFrame frame;
  
  public TimePane() {
    initDisplay();
  }
  
  public void resetPane()
  {
      NBBLthUnit.setTime(0,RuleEditorData.HOURS);
      NBALthUnit.setTime(0,RuleEditorData.HOURS);
      fixOTimeLthUnit.setTime(0,RuleEditorData.MONTHS);
      rangeTimeMinLthUnit.setTime(0,RuleEditorData.MONTHS);
      rangeTimeMaxLthUnit.setTime(0,RuleEditorData.MONTHS);
  }

  private void initDisplay() {
    Dimension dim;

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    JPanel NBPane = new JPanel();
    JPanel NAPane = new JPanel();
       
    NBPane.setBorder(new TitledBorder(new EtchedBorder(), "  notBefore  "));
    NBPane.setLayout(new BoxLayout(NBPane, BoxLayout.X_AXIS));
    //NBPane.setLayout(new GridLayout(1, 2));
    JLabel laterLabel= new JLabel("  Later than current time by as much as: ");
    JLabel beforeLabel= new JLabel("  Before current time by as much as: ");

    dim = new Dimension(650, 120);
    NBPane.setMinimumSize(dim);
    //NBPane.setPreferredSize(dim);
    //NBPane.setMaximumSize(dim);
    NBPane.setLayout(new GridBagLayout());
    NBPane.add(beforeLabel, new GridBagConstraints(0, 0, 1, 1, 100, 100, 
        GridBagConstraints.WEST,
    	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NBPane.add(NBBLthUnit, new GridBagConstraints(1, 0, 1, 1, 100, 100, 
        GridBagConstraints.WEST,
    	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NBPane.add(laterLabel, new GridBagConstraints(0, 1, 1, 1, 100, 100, 
        GridBagConstraints.WEST,
    	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NBPane.add(NBALthUnit, new GridBagConstraints(1, 1, 1, 1, 100, 100, 
        GridBagConstraints.WEST,
    	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    // set default units
    NBBLthUnit.setTime(0,RuleEditorData.HOURS);
    NBALthUnit.setTime(0,RuleEditorData.HOURS);
    
    //NAPane.setLayout(gridBagLayout1);
    NAPane.setBorder(new TitledBorder(new EtchedBorder(), "  notAfter  "));
    //NAPane.setLayout(new GridLayout(5, 2, 5, 5));
    
    fixTButton.setActionCommand("FT");
    fixOButton.setActionCommand("FO");
    rangeButton.setActionCommand("RO");
    fixOButton.setSelected(true);
    
    fixTButton.addActionListener(this);
    fixOButton.addActionListener(this);
    rangeButton.addActionListener(this);
    ButtonGroup NAGroup = new ButtonGroup();
    NAGroup.add(fixTButton);
    NAGroup.add(fixOButton);
    NAGroup.add(rangeButton);
    
    minLabel = new JLabel("      Minimun value:");
    maxLabel = new JLabel("      Maximum value:");
    
    allowFix(false);   
    allowFixO(true);
    allowRange(false);

    dim = new Dimension(650, 250);
    NAPane.setMinimumSize(dim);
    //NAPane.setPreferredSize(dim);
    //NAPane.setMaximumSize(dim);
    NAPane.setLayout(new GridBagLayout());
    NAPane.add(fixTButton, new GridBagConstraints(0, 0, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NAPane.add(fixTimePane, new GridBagConstraints(1, 0, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 175, 0, 0), 0, 0));
    NAPane.add(fixOButton, new GridBagConstraints(0, 1, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NAPane.add(fixOTimeLthUnit, new GridBagConstraints(1, 1, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 175, 0, 0), 0, 0));
    NAPane.add(rangeButton, new GridBagConstraints(0, 2, 2, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NAPane.add(minLabel, new GridBagConstraints(0, 3, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NAPane.add(rangeTimeMinLthUnit, new GridBagConstraints(1, 3, 1, 1, 30,50,
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 175, 0, 0), 0, 0));
    NAPane.add(maxLabel, new GridBagConstraints(0, 4, 1, 1, 30, 50, 
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0));
    NAPane.add(rangeTimeMaxLthUnit, new GridBagConstraints(1, 4, 1, 1, 30, 50,
        GridBagConstraints.WEST,
	GridBagConstraints.NONE, new Insets(0, 175, 0, 0), 0, 0));
    // set default units
    fixOTimeLthUnit.setTime(0,RuleEditorData.MONTHS);
    rangeTimeMinLthUnit.setTime(0,RuleEditorData.MONTHS);
    rangeTimeMaxLthUnit.setTime(0,RuleEditorData.MONTHS);
    
    add(Box.createRigidArea(new Dimension(0,5)));
    add(NBPane);
    add(Box.createRigidArea(new Dimension(0,5)));
    add(NAPane);
    add(Box.createVerticalGlue());
    //setAlignmentX(Component.LEFT_ALIGNMENT);
    setBorder(new TitledBorder(new EtchedBorder(), "  Validity Dates Rule  "));
    
  } 
  
  public void actionPerformed(java.awt.event.ActionEvent e) {
    myRadioChoice = e.getActionCommand();
    Object mySrc = e.getSource();
    
    if (mySrc == fixTButton) { 
      // enable fixTimePane, 
      //disble fixOTimeLthUnit, rangeTimeMinLthUnit, rangeTimeMaxLthUnit
      // Gray out minLabel, maxLabel
      allowFix(true);
      allowFixO(false);
      allowRange(false);
    }
    else if (mySrc == fixOButton) {
      allowFix(false);
      allowFixO(true);
      allowRange(false);
    }
    else if (mySrc == rangeButton) {
      allowFix(false);
      allowFixO(false);
      allowRange(true);      
    }
  }

  private void allowFix(boolean b) {
    fixTimePane.setEnabled(b);
  }

  private void allowFixO(boolean b) {
    fixOTimeLthUnit.setEnabled(b);
  }

  private void allowRange(boolean b) {
    rangeTimeMinLthUnit.setEnabled(b);
    rangeTimeMaxLthUnit.setEnabled(b);
    minLabel.setEnabled(b);
    maxLabel.setEnabled(b);

  }

  public int createRule(Member m) {
    boolean nbaMonthUnit = false;
    int nbaTimeLth = 0;
    boolean nbbMonthUnit = false;
    int nbbTimeLth = 0;
    boolean naMonthUnit= false;
    int naTimeLth = 0;
    boolean naMinMonthUnit = false;
    int naMinLth = 0;
    boolean naMaxMonthUnit = false;
    int naMaxLth = 0;
    int numUnitA, numUnitB;
    String unitA, unitB;
    String timeStr;
    AsnGeneralizedTime genTime = new AsnGeneralizedTime();
    DateRule d;
    TimeUnit  timeUnit, timeUnitA, timeUnitB;
    String msg = "";

    AsnIntRef naFixtime = new AsnIntRef();
    // get time data
    // Not Before
    numUnitA = getNBATime().getLth();
    unitA = getNBATime().getUnit();
    numUnitB = getNBBTime().getLth();
    unitB = getNBBTime().getUnit();
    timeUnitA = TimeUnit.getTimeLth(numUnitA, unitA);
    timeUnitB = TimeUnit.getTimeLth(numUnitB, unitB);
    nbaTimeLth = timeUnitA.getUnitLth();
    nbbTimeLth = timeUnitB.getUnitLth();
    // System.out.println("A = " + nbaTimeLth + " B = " + nbbTimeLth);
    nbaMonthUnit = timeUnitA.getMonthBool();
    nbbMonthUnit = timeUnitB.getMonthBool(); 
  
    // Not after
    if (myRadioChoice == "FT") {
      String str = getNAFTTime();
      if (str == null) {
	  //JOptionPane.showMessageDialog(frame, 
	  //"Please fix \"ValidityDates\".  Fixed time requires Date format.");
	return RuleEditorData.FAILED;
      }
      if (!str.endsWith("Z"))
	  str = str + "Z";
      genTime.write(str);
      genTime.read(naFixtime);
      //System.out.println(" Not after time read " + naFixtime.val);
    }
    else if (myRadioChoice == "FO") {
       timeUnit = TimeUnit.getTimeLth(getNAFOTime().getLth(), 
			     getNAFOTime().getUnit());
       naTimeLth = timeUnit.getUnitLth();
       if (naTimeLth == 0) {
	 JOptionPane.showMessageDialog(frame,
	    "Please fix \"ValidityDates\".  notAfter value should not be 0."); 
	 return RuleEditorData.FAILED;
       }
       naMonthUnit = timeUnit.getMonthBool();  
    }
    else if (myRadioChoice == "RO") {
      minTimeUnit = TimeUnit.getTimeLth(getNAROTime().getMinTime().getLth(), 
			    getNAROTime().getMinTime().getUnit());
      naMinLth = minTimeUnit.getUnitLth();
      naMinMonthUnit = minTimeUnit.getMonthBool(); 
      maxTimeUnit = TimeUnit.getTimeLth(getNAROTime().getMaxTime().getLth(), 
			    getNAROTime().getMaxTime().getUnit()); 
      naMaxLth = maxTimeUnit.getUnitLth();
      naMaxMonthUnit = maxTimeUnit.getMonthBool(); 
    }
 
    m.name.write("Validity Dates");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x00A0
    m.rule.add();
    RuleChoice rc = m.rule.ref;

    rc.sequence.members.member.index(0).insert();
    Member m1 = (Member)rc.sequence.members.member.index(0);
    m1.name.write("notBefore");
    m1.tagtype.write(AsnStatic.ASN_UTCTIME); //0x17
    m1.rule.add();
    d = (DateRule)m1.rule.ref.date;// DateRule 
    d.min.write(-nbbTimeLth); // time before clock must be negative
    d.max.write(nbaTimeLth);
    if (nbbMonthUnit) 
	d.momin.write(AsnStatic.ASN_BOOL_TRUE);
    if (nbaMonthUnit) 
	d.momax.write(AsnStatic.ASN_BOOL_TRUE);
    d.ref.write(""); // Reference to current

    rc.sequence.members.member.index(1).insert();
    Member m2 = (Member)rc.sequence.members.member.index(1);
    m2.name.write("notAfter");
    m2.tagtype.write(AsnStatic.ASN_UTCTIME); //0x17
    m2.rule.add();
    d = (DateRule)m2.rule.ref.date;// DateRule 
    if (myRadioChoice == "FT") {
      d.min.write(0); 
      d.max.write(naFixtime.val); // second, no momin and momax 
      //System.out.println(" Notafter fix time: " + naFixtime.val);
      //ref is omitted to indicate absolute time
    }
    else if (myRadioChoice == "FO") {
      d.min.write(naTimeLth); 
      d.max.write(naTimeLth);
      if (naMonthUnit) 
        {
	d.momin.write(AsnStatic.ASN_BOOL_TRUE);
	d.momax.write(AsnStatic.ASN_BOOL_TRUE);
        }
      d.ref.write("-"); // Reference to notBefore
    }
    else if (myRadioChoice == "RO") {
      if (!maxTimeUnit.greaterThan(minTimeUnit)) {
	JOptionPane.showMessageDialog(frame,
        "Please fix \"ValidityDates\". \n"  +
	"Maximum value (" + maxTimeUnit + ") is not greater than " +
	"minimum value (" + minTimeUnit + ")"); 
	return RuleEditorData.FAILED;
      }
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
    int lth, lthL, lthH;
    AsnByteArray time;
    String unit;
    AsnIntRef i = new AsnIntRef();
    AsnIntRef l = new AsnIntRef();
    AsnIntRef h = new AsnIntRef();
    AsnByteArray aba = new AsnByteArray();

    boolean mon = false;
    AsnGeneralizedTime genTime = new AsnGeneralizedTime();   
    DateRule d = new DateRule();
    TimeUnit tu;  // doesn't have simple constructor
    if (m != null && m.rule != null && m.rule.ref != null &&
      m.rule.ref.sequence != null && m.rule.ref.sequence.members != null)
      {
      Member m1 = m.rule.ref.sequence.members.member.index(0);
      if (m1 != null && m1.rule != null && m1.rule.ref != null &&
        m1.rule.ref.date != null)
        {
        d = m1.rule.ref.date; 
        d.max.read(i);
        d.momax.read(aba);    
        tu = new TimeUnit(i.val, checkAsnBool(aba));
        lth = tu.getDisplayTime();
        unit = tu.getDisplayTimeUnit();
        NBALthUnit.setTime(lth, unit);      
        d.min.read(i);
        d.momin.read(aba);
        tu = new TimeUnit(i.val, checkAsnBool(aba));
        lth = tu.getDisplayTime();
        unit = tu.getDisplayTimeUnit();
        NBBLthUnit.setTime(lth, unit);
        }
      Member m2 = m.rule.ref.sequence.members.member.index(1);
      if (m2 != null && m2.rule != null && m2.rule.ref != null &&
        m2.rule.ref.date != null)
        {
        d = (DateRule)m2.rule.ref.date;
        d.min.read(l);
        d.max.read(h);
        if (l.val == 0) 
          { // FT
          genTime.write(h.val);
          int size = genTime.vsize();
          time = new AsnByteArray(size);
          genTime.read(time);
          //System.out.println(" Not after time (FT): " + time); 
          fixTButton.setSelected(true);
          String tmp = time.toString();
	  if (tmp.endsWith("Z"))
	  {
	      //System.out.println("String is " + tmp);
	      tmp = tmp.substring(0,tmp.length() - 1);
	      //System.out.println("Stripped off Z.  String is " + tmp);
	  }
          fixTimePane.setTime(tmp.trim()); 
	  // checkDate returns true if there is an error
	  if (fixTimePane.checkDate())
	  {
	      fixTimePane.setTime("");
	      return false;
	  }
          allowFix(true);    
          allowFixO(false);
          allowRange(false);
          myRadioChoice = "FT";
          }
        else if (l.val == h.val) 
          { // FO
          d.momax.read(aba);
          tu = new TimeUnit(h.val, checkAsnBool(aba));
          lth = tu.getDisplayTime();
          unit = tu.getDisplayTimeUnit();
          //System.out.println(" Not after time (FO): " + lth + " " + unit);
          fixOButton.setSelected(true);
          allowFix(false);
          allowFixO(true);
          fixOTimeLthUnit.setTime(lth, unit);
          allowRange(false);
          myRadioChoice = "FO";
          }
        else 
          { // RO
          rangeButton.setSelected(true);
          allowFix(false);
          allowFixO(false);
          allowRange(true);
          d.momin.read(aba);
          tu = new TimeUnit(l.val, checkAsnBool(aba));
          lth = tu.getDisplayTime();
          unit = tu.getDisplayTimeUnit();
          //System.out.println(" Not after time (RO, low): " + lth + " " + unit);
          rangeTimeMinLthUnit.setTime(lth, unit);
          d.momax.read(aba);
          tu = new TimeUnit(h.val, checkAsnBool(aba));
          lth = tu.getDisplayTime();
          unit = tu.getDisplayTimeUnit();
          //System.out.println(" Not after time (RO, high): " + lth + " " + unit);
          rangeTimeMaxLthUnit.setTime(lth, unit);
          myRadioChoice = "RO";
          }
        }
      }
    return true;
  }
  
    public boolean checkAsnBool(AsnByteArray aba)
    {
	byte[] val = aba.getArray();
	if (val[0] == 0)
	    return false;
	else
	    return true;
    }

  public void print() {
    getNBATime().print("\n NotBefore min time: "); 
    getNBBTime().print("\n NotBefore max time: "); 
    //System.out.println(" NotAfter Choice: " 
    //	       + getNAChoice());
    if (myRadioChoice == "FT") {
      fixTimePane.print();//System.out.println(" Fix time: " + getNBFTTime());
    }
    else if (myRadioChoice == "FO") {
      fixOTimeLthUnit.print("   Fixed offset time: "); 
    }
    else if (myRadioChoice == "RO") {
      getNAROTime().print(" Range Value:");
    }
  }
  
  public TimeData getNBATime() {
    return (NBALthUnit.getTime());  
  }
  
  public TimeData getNBBTime() {
    return (NBBLthUnit.getTime());  
  }
  
  public String getNAChoice() {
    return myRadioChoice;
  }
  
  public Object getNAObject() {
    return mySrc;
  }
  
  public String getNAFTTime() {
    //System.out.println(" getNAFTTime: " + fixTimePane.getTime());
    boolean error = fixTimePane.checkDate();
    if (!error)  
	return (fixTimePane.getTime());
    else
	return null;
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
  
 
} //Timepane




