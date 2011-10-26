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

public class AutoSystemPane extends ExtnFieldBasePane {
  String[] asnList;
    //String[] rdiList;
  IPPane asnPane;
    //IPPane rdiPane;
  private JFrame frame;

  public AutoSystemPane(String name, String[] listasn, String[] listrdi) {
    super(name, "Require");
    if (RuleUtils.cert == null)
	asnList = null;
    else
	asnList = RuleUtils.cert.getAsnList();
    asnPane.setList(asnList);
    int i;

  }

  public String[] getValues(Integer[] list)
  {
      String[] retList = new String[list.length];
      for (int i=0; i< list.length; i++)
      {
	  //System.out.println("getting item at " + list[i].intValue());
	  retList[i] = asnList[list[i].intValue()];
      }
      return retList;
  }

  public int getListSize()
  {
      if (asnList == null)
	  return 0;
      return asnList.length;
  }

  public void setContentPane() { 
    // WARNING!! this gets called from super() of the constructor
    // it is called before any other setup for this object.
    asnPane = new IPPane(" Autonomous System Number ");
    //rdiPane = new IPPane(" Routing Domain Identifiers ");

    //contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.X_AXIS)); 
    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    contentPane.add(asnPane);
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    //contentPane.add(rdiPane);
    //contentPane.add(Box.createVerticalGlue());

  }

  private void addList(Member m, String[] tmp) {
    int pos, low, high;
    
    m.rule.add();
    SpecialRule s = m.rule.ref.special;
    s.type.write(0x08); // 
    for (int i = 0; i < tmp.length; i++) {
      String str = tmp[i];
      //System.out.println(" asnPane addList(): " + str);
      s.value.addrRanges.range.index(i).insert();
      Range r = s.value.addrRanges.range.index(i);
      if ((pos = str.indexOf("-")) > 0) {
	low = Integer.parseInt(str.substring(0, pos).trim());
	high = Integer.parseInt(str.substring(pos+1).trim());
      } else {
	low = Integer.parseInt(str);
	high = low;
      }
      //System.out.println(" Low: " + low + " High: " + high);
      r.lo.number.write(low);
      r.hi.number.write(high);
    }

  }

  private boolean getListFromRule(Member m, IPPane pane) {
    AsnIntRef lo, hi;
    lo = new AsnIntRef();
    hi = new AsnIntRef();
    SpecialRule s = m.rule.ref.special;
    int ni = s.value.addrRanges.numitems();
    String[] str = new String[ni];
    for (int i = 0; i < ni; i++) {
      Range r = s.value.addrRanges.range.index(i);
      r.lo.number.read(lo);
      r.hi.number.read(hi);
      //System.out.println(" low: " + lo.val);
      //System.out.println(" high: " + hi.val);      
      if (lo.val == hi.val) { //single value
	str[i] = Integer.toString(lo.val);
      } else { // range value
	str[i] = Integer.toString(lo.val) + " - " + Integer.toString(hi.val);
      }
    }
    String[] caList = RuleUtils.cert.getAsnList();
    if (RuleUtils.isASubsetB(str,caList))
    {
	setListContents(str, pane);
	return true;
    }
    System.out.println("Error in AS rule.");
    return false;
  }

  private void addMember(Member m, String[] tmp, IPPane pane) {
    String choice = pane.getInheritChoice();

    m.rule.ref.sequence.members.member.index(0).insert();
    Member m1 = (Member)m.rule.ref.sequence.members.member.index(0);
    m1.rule.add();
    
    if (choice == RuleEditorData.REQUIRE) {
      // can only have boolean true
      Rule p = m1.rule.ref.primitive;
      p.targets.require.target.index(0).insert();
      ((Target)p.targets.require.target.index(0)).tagtype.write(AsnStatic.ASN_NULL);
    } else if (choice == RuleEditorData.PROHIBIT) {
      // can only have seq of num or ranges
      addList(m1, tmp);                     
    } else if (choice == RuleEditorData.ALLOW) {
      // choice: can have boolean or seq of num or ranges
      // inherit choice
      /* m1.rule.ref.sequence.members.member.index(0).insert();
      Member m1s = m1.rule.ref.sequence.members.member.index(0);
      m1s.rule.add();*/

      m1.rule.ref.choice.member.index(0).insert();
      Member m11 = m1.rule.ref.choice.member.index(0);
      m11.name.write("inherit");
      m11.tagtype.write(AsnStatic.ASN_NULL); //0x

      // asNumOrRanges
      m1.rule.ref.choice.member.index(1).insert();
      Member m12 = m1.rule.ref.choice.member.index(1);
      m12.name.write("asNumbersOrRanges");
      m12.tagtype.write(AsnStatic.ASN_SEQUENCE);

      addList(m12, tmp);

    }

  }

  private boolean readMemberFromRule(Member m, IPPane pane) {
    AsnIntRef tagRef = new AsnIntRef();;
    Member m1 = (Member)m.rule.ref.sequence.members.member.index(0);
    m1.rule.ref.tag(tagRef);
    boolean retVal = true;
    //System.out.println(" rule choice: " + tagRef.val);
    switch(tagRef.val) {
    case 0xe7: // primitive, boolean true  
      pane.clearList();
      pane.setInheritChoice(RuleEditorData.REQUIRE);
      retVal = getListFromRule(m1,pane);
      //System.out.println("Inherit choice: " + RuleEditorData.REQUIRE); 
      break;
    case 0xed: // special 
      pane.setInheritChoice(RuleEditorData.PROHIBIT);
      retVal = getListFromRule(m1, pane);
      //System.out.println("Inherit choice: " + RuleEditorData.PROHIBIT); 
      break;
    case 0xe5: // choice allow
      pane.setInheritChoice(RuleEditorData.ALLOW);
      Member m12 = m1.rule.ref.choice.member.index(1);
      retVal = getListFromRule(m12, pane);
      //System.out.println("Inherit choice: " + RuleEditorData.ALLOW); 
      break;
    default:
      JOptionPane.showMessageDialog(frame, "Invalid choice in " + myName + " rule set"); 
        return false;
    }
    return retVal;
  }

  public int createRule(Member m) {
    String[] tmpAsn =  asnPane.getList();
    //String[] tmpRdi = rdiPane.getList();

    //if (tmpAsn.length == 0 && tmpRdi.length == 0) {
    if (tmpAsn.length == 0 ){
      int ans = JOptionPane.showConfirmDialog(frame,
				    "The Autonomous System Identifier extension appears to be empty."
				    + "\nAre you sure you retrieved the correct CA certificate?"
				    + "\nAre you sure you want to do this?"); 
	if (ans == JOptionPane.YES_OPTION) {
	  // continue
	  return RuleEditorData.OK; // OK to have no IP Address Block
	} else if (ans == JOptionPane.NO_OPTION || ans == JOptionPane.CANCEL_OPTION ) {
	  JOptionPane.showMessageDialog(frame, "Please fix the \"Autonomous System Identifier\" error."); 
	  return RuleEditorData.FAILED;
	} 
    }
    m.name.write("Autonomous System ID");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();

    m.rule.ref.sequence.members.member.index(0).insert();
    Member m1 = (Member)m.rule.ref.sequence.members.member.index(0);
    m1.name.write("asnum");
    m1.tagtype.write(AsnStatic.ASN_CONT_CONSTR); //0xa0
    m1.optional.write(AsnStatic.ASN_BOOL_TRUE);
    m1.rule.add();
    
    addMember(m1, tmpAsn, asnPane);

    /*
    if (rdiList != null) {
      m.rule.ref.sequence.members.member.index(1).insert();
      Member m2 = (Member)m.rule.ref.sequence.members.member.index(1);
      m2.name.write("rdi");
      m2.tagtype.write(AsnStatic.ASN_CONT_CONSTR | 1); //0xa1
      m2.optional.write(AsnStatic.ASN_BOOL_TRUE);
      m2.rule.add();
      
      addMember(m2, tmpRdi, rdiPane);
    }
    */
    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
    Member m1 = (Member)m.rule.ref.sequence.members.member.index(0);
    //System.out.println(" AS pane");
    return readMemberFromRule(m1, asnPane);
    //Member m2 = (Member)m.rule.ref.sequence.members.member.index(1);
    //System.out.println(" RDI pane");
    //readMember(m2, rdiPane);
  }

    public void resetListFromCA()
    {
	asnPane.clearList();
	if (RuleUtils.cert == null)
	  return;
	asnPane.clearList();
	asnList = RuleUtils.cert.getAsnList();
	asnPane.setBaseList(asnList);
    }

    public void setBaseList(String [] newList)
    {
	asnPane.clearList();
	asnPane.setBaseList(newList);
    }

    public void setListContents(String[] newList)
    {
	setListContents(newList, asnPane);
    }

    public void setListContents(String[] newList, IPPane pane)
    {
	pane.clearList();
	pane.setList(newList);
    }
}
