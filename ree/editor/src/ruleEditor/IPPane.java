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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class IPPane extends DisplayEntryPane 
  implements ListSelectionListener, RuleListener {

  JLabel label;
  private JTextField edit;
  private Dimension dim;
  private ThreeWayCombo inherit;
    //private JButton addButton;
    //private JButton editButton;
  private JButton removeButton, restoreButton;
  private JFrame frame;
  private String inheritChoice;
  //private String myTitle;
  private String[] myList;
  private String safiStr; // safi should not be changed during editing.
  private TabListCellRenderer renderer; 
  String[] origList;
  
  public IPPane(String title) {
    super(title);

    //myTitle = title;
    inheritChoice = RuleEditorData.PROHIBIT;
  }

    /***
       setBaseList is intended to be called when a new CA certificate is opened.
       It will set the variable origList and call setList to set the contents of the 
       GUI display.
    ***/

  public void setBaseList(String [] list)
  {
      origList = list;
      setList(list);
  }

  public void setList(String[] list) {
    if (list != null) {
      clearList();
      myList = list; // ??
      super.setList(list);
      inherit.setEnabled(true);
      if (list[0].indexOf("INHERIT") == 0) { // The first and only one 
	inherit.setChoice(RuleEditorData.REQUIRE);
	inheritChoice = RuleEditorData.REQUIRE;
      }
    } else {
      super.setEnabled(false);
    }
  }

 public void actionPerformed(java.awt.event.ActionEvent e) {
    super.actionPerformed(e);
    String command = e.getActionCommand();
    if (command.equals("Restore"))
    {
	clearList();
	setList(origList); // 
    }

  }

 public void setInputPane(JPanel inputButtonPane, String inputTitle, String[] name) {

    inherit = new ThreeWayCombo("Inherit from Issuer: ", RuleEditorData.PROHIBIT); 
    inherit.addRuleListener(this);

    renderer = new TabListCellRenderer();
    renderer.setTabs(new int[] {50, 200, 300});
    list.setCellRenderer(renderer);

    //inherit.setBorder(BorderFactory.createRaisedBevelBorder());
    //inherit.setAlignmentX(Component.RIGHT_ALIGNMENT);
    inherit.setAlignmentX(Component.CENTER_ALIGNMENT);

    //addButton = new JButton("Add");
    //addButton.setPreferredSize(RuleEditorData.shortField);
    //addButton.setMinimumSize(RuleEditorData.shortField);
    //addButton.setMaximumSize(RuleEditorData.shortField);
    //addButton.setActionCommand("Add");
    //addButton.addActionListener(new addListener());
    //addButton.addActionListener(this);
 
    //editButton = new JButton("Edit");
    //editButton.setPreferredSize(RuleEditorData.shortField);
    //editButton.setMinimumSize(RuleEditorData.shortField);
    //editButton.setMaximumSize(RuleEditorData.shortField);
    //editButton.setActionCommand("Edit");
    //editButton.addActionListener(new addListener());
    //editButton.addActionListener(this);

    removeButton = new JButton("Remove");
    removeButton.setPreferredSize(RuleEditorData.shortField);
    removeButton.setMinimumSize(RuleEditorData.shortField);
    removeButton.setMaximumSize(RuleEditorData.shortField);
    //removeButton.setEnabled(false);
    removeButton.setActionCommand("Remove");
    removeButton.addActionListener(this);

    restoreButton = new JButton("Restore from CA");
    restoreButton.setMinimumSize(RuleEditorData.shortField);
    //removeButton.setEnabled(false);
    restoreButton.setActionCommand("Restore");
    restoreButton.addActionListener(this);

    JPanel buttonPane = new JPanel();
    buttonPane.add(removeButton);
    buttonPane.add(restoreButton);
    buttonPane.setPreferredSize(RuleEditorData.largeField);
    buttonPane.setMinimumSize(RuleEditorData.largeField);
    buttonPane.setMaximumSize(RuleEditorData.largeField);
    //buttonPane.setBorder(BorderFactory.createRaisedBevelBorder());
    
    // Create a panel house input
    edit = new JTextField(); 
    Dimension dim = new Dimension(300, 25);
    edit.setMinimumSize(dim);
    edit.setPreferredSize(dim);
    edit.setMaximumSize(dim);
    edit.setActionCommand("Add");
    edit.addActionListener(this);

    /*
    JPanel inputPane = new JPanel();
    inputPane.setLayout(new BoxLayout(inputPane, BoxLayout.X_AXIS));
    label = new JLabel("Edit number: ");
    inputPane.add(label);
    inputPane.add(edit);
    //inputPane.setBorder(BorderFactory.createRaisedBevelBorder());
    */

    inputButtonPane.setLayout(new BoxLayout(inputButtonPane, BoxLayout.Y_AXIS));
    //inputButtonPane.add(Box.createRigidArea(new Dimension(0,5)));
    if (myTitle.indexOf("Router") < 0) { // non router ID
      inputButtonPane.add(inherit);
    }
    //inputButtonPane.add(Box.createRigidArea(new Dimension(0,5)));
    inputButtonPane.add(buttonPane);
    //inputButtonPane.add(inputPane);

  } 

  public void setInputPaneEnabled(boolean b) {
    setInputPanePartialEnabled(b);
    if (!b) {
      removeButton.setEnabled(false);
    }
    inherit.setEnabled(b);

  }

  public void setInputPanePartialEnabled(boolean b) {
    if (list.getSelectedIndex() == -1) {
      //nothing, disable remove button.
      removeButton.setEnabled(false);
    } else {
      //enable remove button.
      removeButton.setEnabled(b);
    }
   }
  
  public void enableRemoveButton(boolean b) {
    if (list.getSelectedIndex() == -1) {
      removeButton.setEnabled(false);
    } else {
      removeButton.setEnabled(b);
    }  
  }

  private boolean checkV4data(String str) {
    int data = Integer.parseInt(str.trim());
    if (data >= 0 && data <= 255) {
      return true;
    } else {
      JOptionPane.showMessageDialog(frame,
		  "IPv4 address is out of range ( 0..255)."); 
      return false;
    }
  }

  private boolean checkV6data(String str) {
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if ((c >= '0' && c <= '9')||
	  (c >= 'a' && c <= 'f') ||
	  (c >= 'A' && c <= 'F')) {
	// ok
	//System.out.println("  checkV6data OK.");
      } else {
      JOptionPane.showMessageDialog(frame,
				    "IPv6 address is out of range (0000..FFFF)."); 
      return false;
      }
    }

    return true;
  }

  private boolean checkAddr(String str, 
			    String separator, 
			    String otherSeparator) {
    int type;
    //String address;
    int maxNum;
    boolean correct, stop = false;
    int radical;
    int indexS = 0, indexE = 0, end, address, numDecimal = 0;
    String s;
    
    if (separator.equals(".")) { // v4
      type = 1; // v4
      maxNum = 4;
      radical = 10;
    } else {
      type = 2; // v6
      maxNum = 8;
      radical = 16;
    }
    if (str.indexOf(otherSeparator) > 0) {
      JOptionPane.showMessageDialog(frame,
				    "Wrong IP address separator."); 
      
      return false;
    }
    
    end = str.lastIndexOf(separator);
    if (end == -1) { // top level number only
      //System.out.println("str " + str);
      //address = Integer.parseInt(str.trim(), radical);
      if (type == 1) {
	correct = checkV4data(str.trim());
	//System.out.println("checkAddr v4: " + correct); 
      } else {
	correct = checkV6data(str.trim());
	//System.out.println("checkAddr v6: " + correct); 
      }
      return correct;
    }
    
    while (!stop) {
      numDecimal ++;
      if (indexE != end) { 
	indexE = str.indexOf(separator, indexS);
	s = str.substring(indexS, indexE);
      } else {
	s = str.substring(indexS);
	stop = true;
      }
      
      //System.out.println("indexS: " + indexS + " indexE: " + indexE +" s: " + s);
      //address = Integer.parseInt(s.trim(), radical);
      if (type == 1) {
	if (!checkV4data(s.trim()) || numDecimal > 4)
	  return false; 
      } else {
	if (!checkV6data(s.trim()) || numDecimal > 8)
	  return false; 
      }
      if (stop) { // reach last decimal
	return true;
      } 
      indexS = indexE + 1;
    } // while

    return true;

  }
  
  private boolean checkData(String str) {
    // check data to be compliant to the format and unique
    boolean correct;
    int end;
    
    if ((end = str.indexOf("/")) > 0) {
      str = str.substring(0, end).trim();
    }
    if (myTitle.indexOf("v4") >= 0) { //x.x.x.x upto 4 decimal
      correct = checkAddr(str, ".", ":");
      //System.out.println("checkIPData v4: " + str+ " " +correct);

    } else { // v6: x:x::x:(up to 8 int
      correct = checkAddr(str, ":", ".");
      //System.out.println("checkIPData v6: " + str + " " + correct);
    }

    return correct;
   
  }

  private boolean checkIPData(String str) {
    int indexS = 0, indexE = 0, end, address;
    String s;

    str = getAddrSubstring(str); 
    if ((indexE = str.indexOf("-")) > 0) { // range value
      for(int i = 0 ; i < 2; i++) {
	s = str.substring(indexS, indexE);
	if (!checkData(s))
	  return false;
	indexS = indexE+1;
	indexE = str.length();
      }
      return true;
    } else { // single value
      return checkData(str);
    }

  }

  private boolean checkUnique(String str) {
    String[] list = getList();

    for (int i = 0; i < list.length; i++) {
      if (str.equals(list[i])) {
	return false;
      }
    }

    return true;

  }

  private boolean checkWithinRange(String text) {
    String safi, safiL, data, inherit, texts;
    String lead = new String(), leads = new String();
    int i, n, high = 0, low = 0;
    int loI = 0, loHiI = 0, hiLoI = 0, hiI = 0, num = 0;
    StringTokenizer st, sts;
    boolean rangeData = false;
    boolean inRange = false;
    Address addr;

    if (myTitle.indexOf("IP") >= 0) { // Check IP address
      // SAF# \t address
      st = new StringTokenizer(text, "\t");
      n = st.countTokens(); 
      if (n == 0)
	  return true;
      safi = st.nextToken().trim();
      data = st.nextToken().trim();
      if (n == 3) {
	inherit = st.nextToken().trim();
      } else {
	inherit = null;
      }
      //System.out.println(" Handling input data: "+ text);
      addr = new Address(data, myTitle);
      rangeData = addr.getRange();
      //System.out.println(" In checkWithinRange. range: " + rangeData);
      if (rangeData) { 
	loI = addr.getLo();
	loHiI = addr.getLoHi();
	hiLoI = addr.getHiLo();
	hiI = addr.getHi();
	//System.out.println(" " + loI + " " + loHiI + " " + hiLoI + " " + hiI);
	if (!addr.getLegal()) {
	  return false;
	}
      } else {
	loI = addr.getLo();
	hiI = addr.getHi();
      }

      //System.out.println(" Handling list data");
      // check with list
      for (i = 0; i < myList.length; i++) {
	int lo = 0, loHi = 0, hiLo = 0, hi = 0;
	st = new StringTokenizer(myList[i], "\t");
	safiL = st.nextToken().trim();
	data = st.nextToken().trim();
	addr = new Address(data, myTitle);
	rangeData = addr.getRange();
	if (rangeData) { 
	  lo = addr.getLo();
	  loHi = addr.getLoHi();
	  hiLo = addr.getHiLo();
	  hi = addr.getHi();
	} else {
	  lo = addr.getLo();  
	  hi = addr.getHi();
	}
	//System.out.println("list[" + i + "]: " + lo + " " + hi);
	if (loI >= lo && hiI <= hi) {
	  //System.out.println("Input: " + loI + " " + hiI);
	  //System.out.println("inRange true");
	  inRange = true; // within range
	}
	if (inRange) {
	  if (checkUnique(myList[i])) {
	    // this entry has been removed, so safe to add the modified one
	    return true;
	  } else {
	    return false; // overlap with existing list
	  }
	}
      }      
    } else {// Check asNum
      if (text.indexOf("asnum") >= 0 || text.indexOf("rdi") >= 0) {
	sts = new StringTokenizer(text, "\t");
	lead = sts.nextToken().trim();
	text = sts.nextToken().trim();
      }
      if (text.indexOf("-") > 0) { // get input data
	st = new StringTokenizer(text, "-");
	String a = st.nextToken().trim();
	String b = st.nextToken().trim();
	if (!RuleUtils.isDigit(a) || !RuleUtils.isDigit(b)) {
	  JOptionPane.showMessageDialog(frame,
					"AS number should be integer "); 
	  return false;	      
	}
	low = Integer.parseInt(a);
	high = Integer.parseInt(b);
	rangeData = true;
	//System.out.println("inRange low: " + low + " high: " + high);
      } else { // single num
	if (text.indexOf("asnum") >= 0 || text.indexOf("rdi") >= 0) {
	  sts = new StringTokenizer(text, "\t");
	  lead = sts.nextToken().trim();
	  text = sts.nextToken().trim();
	}
	String tmp = text.trim();
	if (!RuleUtils.isDigit(tmp)) {
	  JOptionPane.showMessageDialog(frame,
					"AS number should be integer "); 
	  return false;	      
	}
	num = Integer.parseInt(tmp);

	//System.out.println("inRange num: " + num);
      }
      // check input data against with certificate list (myList) data to check wihtin range
      for (i = 0; i < myList.length; i++) {
	if (myList[i].indexOf("asnum") >= 0 || myList[i].indexOf("rdi") >= 0) {
	  sts = new StringTokenizer(myList[i], "\t");
	  leads = sts.nextToken().trim();
	  texts = sts.nextToken().trim();
	} else {
	    texts = myList[i];
	}
	if (texts.indexOf("-") > 0) {
	  if (leads.equals(lead)) {
	    st = new StringTokenizer(texts, "-");
	    int a = Integer.parseInt(st.nextToken().trim());
	    int b = Integer.parseInt(st.nextToken().trim());
	    //System.out.println("inRange list[" + i + "] low: " + a + " high: " + b);
	    
	    if (!rangeData) {
	      if (num >= a && num <= b) {
		//System.out.println("inRange true");
		//check overlapping
		inRange = true;
	      }
	    } else {
	      if (low >= a && high <= b) {
		//System.out.println("Inrange true");
		inRange = true;
	      }
	    }
	  }
	  if (inRange) {
	    if (checkUnique(myList[i])) { 
	      // this entry has been removed, so safe to add the modified one
	      return true; 
	    } else { // overlap with existing list
	      return false;
	    }
	  }
	  
	}
      } 
    } 
    
    return false;
  }
    
  public String getInputValue(ActionEvent e, String command) {
    String choice = e.getActionCommand();
    String text = null;
    boolean unique;
    
    text = edit.getText().trim();
    //System.out.println(" input text: " + text);
    if (command.equals("Edit")) {
      return text;
    }

    unique = checkUnique(text);   
    if (!unique) {
      if (myTitle.indexOf("IP") >= 0) {
	JOptionPane.showMessageDialog(frame,
				      "This Ip address is in the list already."); 
      } else { // As num
	JOptionPane.showMessageDialog(frame,
				      "This number is in the list already."); 
      }
      return "";
    }
    boolean inRange = checkWithinRange(text);
    if (!inRange) {
      if (myTitle.indexOf("IP") >= 0) {
	JOptionPane.showMessageDialog(frame,
				      "This Ip address is not in the list range or overlapped with list."); 
      } else { // As num
	JOptionPane.showMessageDialog(frame,
				      "This number is not in the list range or overlapped with list."); 
      }
      return "";
    }
    
    if (myTitle.indexOf("IP") >= 0) {
      String str = getSAFINum(text);
      if (!safiStr.equals(str) ) {
	JOptionPane.showMessageDialog(frame,
				      "SAFI value should not be changed."); 
	return "";
      }
      boolean rightFormat = checkIPData(text);
      if (!rightFormat) {
	//JOptionPane.showMessageDialog(frame,
	//			      "Ip address does not follow the correct formats."); 
	  return "";
      }
    }  // AS number has been checked in checkWithinRange()
    return text;
  }

  public int getInputIndex(String text) {
    StringTokenizer st, sts;
    int n, i, index = 0, low = 0, num = 0, high = 0;
    int loI = 0, loHiI = 0, hiLoI = 0, hiI = 0;
    String safi, safiL, data, inherit, texts;
    String lead = new String(), leads = new String();
    String[] list = getList();
    boolean rangeData = false; // input data is a range Value
    Address addr;

    //System.out.println(" In getInputIndex()");
    if (myTitle.indexOf("IP") >= 0) {
      // SAF# \t address
      st = new StringTokenizer(text, "\t");
      n = st.countTokens(); 
      safi = st.nextToken().trim();
      data = st.nextToken().trim();
      if (n == 3) {
	inherit = st.nextToken().trim();
      } else {
	inherit = null;
      }
      //System.out.println(" Handling input data: "+ text);
      addr = new Address(data, myTitle);
      rangeData = addr.getRange();
      //System.out.println(" In getInputIndex. range: " + rangeData);
      loI = addr.getLo();
      hiI = addr.getHi();
     
      //System.out.println(" Handling list data.  list length: "+ list.length);
      // check with list
      for (i = 0; i < list.length; i++) {
	int lo = 0, loHi = 0, hiLo = 0, hi = 0;
	st = new StringTokenizer(list[i], "\t");
	safiL = st.nextToken().trim();
	data = st.nextToken().trim();
	addr = new Address(data, myTitle);
	rangeData = addr.getRange();
	lo = addr.getLo();  
	hi = addr.getHi();
	//System.out.println("list[" + i + "]: " + list[i] + " " + lo + " " + hi);
	int l = (lo >> 31) & 0x01; // get highest bit of list items low end
	int h = (hiI >> 31) & 0x01; // get highest bit of input high end
	//System.out.println(" list low end, high bit: " + l + " input high end. High bit: " + h);
	if ((l == h && hiI < lo) || h < l) {
	  return i;
	}
      }   
    } else {// asNum
      if (text.indexOf("asnum") >= 0 || text.indexOf("rdi") >= 0) {
	sts = new StringTokenizer(text, "\t");
	lead = sts.nextToken().trim();
	text = sts.nextToken().trim();
      }
      if (text.indexOf("-") > 0) { // get input data
	st = new StringTokenizer(text, "-");
	low = Integer.parseInt(st.nextToken().trim());
	high = Integer.parseInt(st.nextToken().trim());
	rangeData = true;
	//System.out.println("inRange low: " + low + " high: " + high);
      } else { // single num
	num = Integer.parseInt(text.trim());
	//System.out.println("getInputIndex num: " + num);
      }
      // check input data against with list data
      for (i = 0; i < list.length; i++) {
	if (list[i].indexOf("asnum") >= 0 || list[i].indexOf("rdi") >= 0) {
	  sts = new StringTokenizer(list[i], "\t");
	  leads = sts.nextToken().trim();
	  texts = sts.nextToken().trim();
	} else {
	  texts = list[i];
	}
	if (texts.indexOf("-") > 0) { // range list data
	  st = new StringTokenizer(texts, "-");
	  int a = Integer.parseInt(st.nextToken().trim());
	  int b = Integer.parseInt(st.nextToken().trim());
	  //System.out.println("getInputIndex list[" + i + "] low: " + a + " high: " + b);
	  
	  if (!rangeData) {
	    if (num < a) {
	      //System.out.println("getInputIndex index: " + i);
	      return i;
	    } else { // num has to > b
	      continue;
	    }
	  } else { // range
	    if (high < a) {
	      //System.out.println("getInputIndex index: " + i);
	      return i;
	    } else { // low has to > b
	      continue;
	    }
	  }
	} else { // single digit list data
	  if (!rangeData) { // input data not a range value
	    int numL = Integer.parseInt(texts.trim());
	    if (num < numL) {
	      //System.out.println("getInputIndex index: " + i);
	      return i;
	    } else {
	      continue;
	    }
	  }
	}
      }
    }
    return (list.length);
  }

  public void setInputValue(String text, String command){
    edit.setText(text);
    if (myTitle.indexOf("IP") >= 0) {
      safiStr = getSAFINum(text);
      // Reflect the inherit value
      int inheritValue = hasInherit(text);
      inherit.setChoice(RuleEditorData.ThreeWayData[inheritValue-1]);
      
    }
  }

  public String getSAFINum(String text) {
    int indexS = text.indexOf(" ");
    int indexE = text.indexOf("\t");
    String str;
    if (indexS >= 0 && indexE > indexS) str = text.substring(indexS+1, indexE);
    else str = "";
    //System.out.println("getSAFINum: " + str); 
    return str;
  }

  public String getSAFISubstring(String text) {
    int index = text.indexOf("\t");
    String str = text.substring(0, index);
    //System.out.println("getSAFISubstring: " + str); 
    return str;
  }

  public String getAddrSubstring(String text) {
    String str;
    int indexS = text.indexOf("\t");
    int indexE = text.indexOf("\t", indexS+1);
    if (indexE == -1) {
      str = text.substring(indexS + 1);
    } else {
      str = text.substring(indexS + 1, indexE );
    }
    if (str.indexOf("(") != -1) {// remove paren 
      str = str.substring(1, str.length()-1);
    }
    //System.out.println(" getAddrSubstring: " + str);
    return str;
  }

  public String getInheritChoice() {
    //System.out.println(" inheritChoise: " + inheritChoice);
    return inheritChoice;
  }


  public void setInheritChoice(String choice) {
    inheritChoice = choice;
    inherit.setChoice(choice);
  }

  public int hasInherit(String str) { // 1: required, 2: allow, 3: prohibit
    int indexS = -1;
    if (str != null)
      indexS = str.indexOf("INHERIT");
    if (indexS >= 0) {
      if (str.indexOf("(") >= 0) {
	return RuleEditorData.REQUIRE_NUM; //require
      } else {
	return RuleEditorData.ALLOW_NUM; // allow
      }
    }
    else return RuleEditorData.PROHIBIT_NUM; // prohibit
    
  }

  private String addInherit(String str){
    int indexS = -1;

    if (str != null)
      indexS = str.indexOf("INHERIT");
    if (indexS == -1) {
      str = str + "\t" + " INHERIT";
    }
    else if (str.indexOf("(") > 0) { // remove parens
      String safi = getSAFISubstring(str);
      String addr = getAddrSubstring(str);
      str = safi + "\t" + addr + "\t" + " INHERIT ";
    }      
    //System.out.println(" addInherit: " + str);
    return str;
  }

  private String removeInherit(String str) {
    int indexS = -1;

    if (str != null)
      indexS = str.indexOf("INHERIT");
    if (indexS == -1) {
      // do nithing
    }
    else { // remove inherit and parens
      String safi = getSAFISubstring(str);
      String addr = getAddrSubstring(str);
      str = safi + "\t" + addr;
    }      
    //System.out.println(" addInherit: " + str);
    return str;
  }

  private String parenAddressaddInherit(String text){
    String safi = getSAFISubstring(text);
    String addr = getAddrSubstring(text);
    String str = safi + "\t" + "(" + addr + ")" + "\t" + " INHERIT ";
    //System.out.println(" parenAddressaddInherit: " + str);
    return str;
  }

  public void rulePerformed (RuleEvent e) {
    inheritChoice = inherit.getChoice();
    String safiNum;
    int i;
    
    int index = list.getSelectedIndex();
    int size = listModel.getSize();
    String text = (String)list.getSelectedValue();
    if (text != null) {
      text = text.toString();
    }
    
    if (RuleEditorData.ThreeWayData[hasInherit(text)-1] == inheritChoice ) {
      return; // do nothing 
    }

    if (myTitle.indexOf("IP") >= 0) {
      safiNum = getSAFINum(text);
      if (inheritChoice == RuleEditorData.REQUIRE) {
	// Change the address list of the list selected to INHERIT
	for (i = 0; i < size; i++) {
	  text = list.getModel().getElementAt(i).toString();
	  //System.out.println("REQUIRE: size: " + size + " i: " + i + " " + text);
	  if (getSAFINum(text).equals(safiNum)) {
	    text = parenAddressaddInherit(text);
	    listModel.remove(i);
	    listModel.insertElementAt(text, i);
	  }
	}
	super.setPartialEnabled(false); 
      } else if (inheritChoice == RuleEditorData.PROHIBIT) {
	// rmove inherit if any
	for (i = 0; i < size; i++) {
	  text = list.getModel().getElementAt(i).toString();
	  //System.out.println("PROHIBIT: size: " + size + " i: " + i + " " + text);
	  if (getSAFINum(text).equals(safiNum)) {
	    text = removeInherit(text);
	    listModel.remove(i);
	    listModel.insertElementAt(text, i);
	  }
	}
	super.setPartialEnabled(true);
      } else if (inheritChoice == RuleEditorData.ALLOW) {
	// choice: can be inhert true; address list; or afi/safi doesn't exist 
	for (i = 0; i < size; i++) {
	  text = list.getModel().getElementAt(i).toString();
	  //System.out.println("ALLOW: size: " + size + " i: " + i + " " + text);
	  if (getSAFINum(text).equals(safiNum)) {
	    text = addInherit(text);
	    listModel.remove(i);
	    listModel.insertElementAt(text, i);
	  }
	}
	super.setPartialEnabled(true); //enable input pane & list
      }
      list.setSelectedIndex(((index+1) == size)? index: index+1);
    } else { // ASnum
      if (inheritChoice == RuleEditorData.REQUIRE) {
	//disable input pane & list
	super.setEnabled(false);
      } else if (inheritChoice == RuleEditorData.PROHIBIT) {
	// do nothing
	super.setPartialEnabled(true);
      } else if (inheritChoice == RuleEditorData.ALLOW) {
	// a choice in the rule
	super.setPartialEnabled(true);
      }
    }
  }

  class Address {
    private boolean range;
    private int index;
    private byte[] lo4 = new byte[4];
    private byte[] loHi4 = new byte[4];
    private byte[] hiLo4 = new byte[4];
    private byte[] hi4 = new byte[4];

    /* For each address, return the lowest and highest address in 4 bytes allowed.
     * For a range data (has "-"), make sure the "high end of the low" < 
     * the "low end of high".
     */
    public Address(String data, String type) {
      int i, slot, unused;
      StringTokenizer st;

      if (data.indexOf("-") > 0) { // range input data
	range = true;
	st = new StringTokenizer(data, "-");
	String loS = st.nextToken().trim();
	String hiS = st.nextToken().trim();
	st = new StringTokenizer(loS, "/");
	String loNumS = st.nextToken().trim();
	int loBit = Integer.parseInt(st.nextToken().trim());
	if (type.indexOf("v4") > 0) { //v4
	  SingleV4Address addr = new SingleV4Address(loS);
	  lo4 = addr.getLo();
	  loHi4 = addr.getHi();
	  addr = new SingleV4Address(hiS);
	  hiLo4 = addr.getLo();
	  hi4 = addr.getHi();
	} else {  // v6

	}
      } else { // single input data
	range = false;
	if (type.indexOf("v4") > 0) { //v4
	  SingleV4Address addr = new SingleV4Address(data);
	  lo4 = addr.getLo();
	  hi4 = addr.getHi();
	} else { // v6
	  
	}
      }
      //System.out.println(" range: " + range);
    }
    
    private int turnByte2Int(byte[] b) {
      int i, num = 0;
      for (i = 0; i < 4; i++) {
	  //System.out.println("i: " + b[i]);
	num <<= 8;
	num += (0xFF) & b[i];
      }
      //System.out.println(" int: " + num);
      return num;
    }

    public boolean getRange() {
      return range;
    }
    public int getLo() {
      return turnByte2Int(lo4);
    }
    public int getLoHi() {
      return turnByte2Int(loHi4);
    }
    public int getHi() {
      return turnByte2Int(hi4);
    }
    public int getHiLo() {
      return turnByte2Int(hiLo4);
    }
    public boolean getLegal() {
      //System.out.println(" loHi: " + loHi4 + " hiLo: " + hiLo4);
      //System.out.println(" loHi: " + turnByte2Int(loHi4) + " hiLo: " + turnByte2Int(hiLo4));
      if (turnByte2Int(loHi4) > turnByte2Int(hiLo4)) {
	return false; 
      } else {
	return true;
      }
    }
  }  
  
  class SingleV4Address {
    int i, bit, slot, unused, index;
    StringTokenizer st;
    private byte[] lo = new byte[4];
    private byte[] hi = new byte[4];

    public SingleV4Address(String data) {
      st = new StringTokenizer(data, "/");
      String numS = st.nextToken().trim();
      bit = Integer.parseInt(st.nextToken().trim());
      if (numS.indexOf(".") > 0) { // v4 more than one number
	st = new StringTokenizer(numS, ".");
	index = -1;
	while (st.hasMoreTokens()) {
	  lo[++index] = (byte)(Integer.parseInt(st.nextToken().trim()) & 0xFF);
	  hi[index] = lo[index];
	}
      } else {// one data, one number
	lo[0] = (byte)(Integer.parseInt(numS) & 0xFF);
	hi[0] = lo[0];
	index = 0;
      }
      slot = bitSlot(bit);
      unused = bitUnused(bit);
      //byte b = bitPow(unused);
      hi[slot] = bitPow (lo[slot], unused);
      for (i = index + 1; i < 4; i++) {
	lo[i] =(byte)0;
	hi[i] = (byte)(255 & 0xFF);
      }	
    }
    
    private int bitSlot(int num) {
      int slot = (num - 1) / 8;
      //System.out.println(" bit number: " + num + " bit slot: " + slot);
      return slot;
    }
    
    private int bitUnused(int num) {
      int used = mod(num, 8);
      //System.out.println(" used: " + used);
      int unused = 8 - used;
      //System.out.println(" bit number: " + num + " bit unused: " + unused);
      return unused;
    }

    private int mod(int num, int base) {
      int tmp = num;
      //System.out.println(" number: " + num);
      while (tmp > base) {
	tmp -=base;
      }
      //System.out.println(" mod: " + tmp);
      return tmp;
    }

    private byte bitPow(byte b, int n) {
      int i;
      byte res = 1;
      if (n == 0) {
	return b;
      }
		  
      for (i = 1; i < n; i++) {
	res <<= 1;
	res += 1;
      }
      res = (byte)((res + b) & 0xFF);
      //System.out.println(" unused bit: " + n + " res: " + res);
      return res;
    }
    
    public byte[] getLo() {
      return lo;
    }
    
    public byte[] getHi(){
      return hi;
    }
  }
  
  class SingleV6Address { // 16 bytes, 8 pairs of 2 bytes
    
  }
  
  
}
  
