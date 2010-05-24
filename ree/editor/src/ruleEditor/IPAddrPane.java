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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class IPAddrPane extends ExtnFieldBasePane {
  String[] v4List;
  String[] v6List;
  IPPane ipv4Pane;
  IPPane ipv6Pane;
  private JFrame frame;

  public IPAddrPane(String name, String[] list4, String[] list6) {
    super(name, "Require");
    //System.out.println("just called super with require.");
    int i;
    if (RuleUtils.cert == null)
    {
	v4List = null;
	v6List = null;
    } else
    {
	v4List = RuleUtils.cert.getV4List();
	v6List = RuleUtils.cert.getV6List();
    }
    ipv4Pane.setList(v4List);
    ipv6Pane.setList(v6List);
  }

  public void setContentPane() { 
    // BEWARE!! this get executed on super() of the constructor
    // it is called before any other setup for this object.
    ipv4Pane = new IPPane("IPv4 addresses");
    ipv6Pane = new IPPane("IPv6 addresses");

    JSplitPane jsplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
				       ipv4Pane, ipv6Pane);
    jsplit.setContinuousLayout(true);
    //contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.X_AXIS)); 
    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS)); 
    contentPane.add(jsplit);
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    // contentPane.add(ipv4Pane);
    //contentPane.add(Box.createRigidArea(new Dimension(0,5)));
    //contentPane.add(ipv6Pane);
    //contentPane.add(Box.createVerticalGlue());

  }

  public void printValues(String[] list)
  {
      System.out.println("list is: ");
      for (int i=0; i< list.length; i++)
      {
	  System.out.println("element # " + i + " = " + list[i]);
      }
  }

  public String[] getValues(Integer[] list, int type)
  {
      String[] fromList = null;
      if (type == RuleEditorData.IPV4)
      {
	  v4List = ipv4Pane.getList();
	  fromList = v4List;
      }
      else
      {
	  v6List = ipv6Pane.getList();
	  fromList = v6List;
      }
      String[] retList = new String[list.length];
      for (int i=0; i< list.length; i++)
      {
	  //System.out.println("getting item at " + list[i].intValue());
	  retList[i] = fromList[list[i].intValue()];
      }
      return retList;
  }

  public int getCombinedListSize()
  {
      int size = 0;
      v4List = ipv4Pane.getList();
      v6List = ipv6Pane.getList();
      if (v4List != null)
	  size = v4List.length;
      if (v6List != null)
	  size += v6List.length;
      return size;
  }

  private String[] transformV6(String[] num, int count) {
    int i, j;
    String[] newNum = new String[count * 2];

    for (i = 0; i < count; i++) {
      switch(num[i].length()) {
      case 1:
      case 2:
	newNum[i * 2] = "00";
	newNum[i * 2 + 1] = num[i];
	break;
      case 3:
	newNum[i * 2] = num[i].substring(0, 1);
	newNum[i * 2 + 1] = num[i].substring(1);
	break;
      case 4:
	newNum[i * 2] = num[i].substring(0, 2);
	newNum[i * 2 + 1] = num[i].substring(2);
	break;
      default:
       JOptionPane.showMessageDialog(frame, "Invalid choice in IPAddr rule set"); 
        return new String[0];
      }
    }
    
    return newNum;

  }

  private int getV6number(String str, String[] number) {
    int i, j, k, num = -1;
    int start = 0, end = 0;
    boolean stop = false;

    String[] tmp = new String[8];
    while (!stop) {
      end = str.indexOf(":", start);
      if (end < 0) {
	stop = true;
	end = str.length();
      }
      tmp[++num] = str.substring(start, end).trim();
      //System.out.println("v6  number("+ num + "): " + tmp[num]); 
      start = end + 1;
    }
    ++num;
    
    if ((i = str.indexOf("::")) < 0) { // no shorthand
      for (j = 0; j < num; j++) {
	number[j] = tmp[j];
      }
    } else { // deal with ::
      for (j = 0, k = 0; j < num; j++, k++) {
	if (!tmp[j].equals("")) {
	  number[k] = tmp[j];
	  //System.out.println("6  number("+ k + "): " + number[k]); 
	} else { // shorthand one
	  int add = 8 - num + 1; // how many 0 to add to the address, 
	                   // 1 is for this current one
	  for (i = 0; i < add; i++, k++) {
	    number[k] = "00";
	    //System.out.println("6  number("+ k + "): " + number[k]); 
	  }
	  k--;
	}
      }
      num = 8;
    }

    return(num);
  }



  private byte[] getBitString(String str, String separator) {    
    int ub = 0; // int to indicate used bits
    int i, lth; // total bits;
    int num;
    int[] v4number;
    String[] v6number, v6hex = null;
    byte[] v4value, v6value;

    v4number = new int[4];
    v6number = new String[8];
    v4value = new byte[7];
    v6value = new byte[19];
    i = str.indexOf("/");
    if (i > 0) {
      ub = Integer.parseInt(str.substring(i+1)); 
      str =  str.substring(0, i).trim();
      //System.out.println(" Used bit: " + ub + " addr: " + str);
    }

    if (separator.equals(".")) { // v4
      num = RuleUtils.getV4number(str, v4number);
      lth = 8 * num;
    } else { // v6
      num = getV6number(str, v6number);
      lth = 16 * num;
      v6hex = transformV6(v6number, num);
      //for (i = 0; i < v6hex.length; i++) 
      //  System.out.println(v6hex[i]);

    }

    int unusedBit = lth - ub;
    int j;
    if (separator.equals(".")) { // v4
      j = num - (unusedBit / 8);
      v4value[0] = (byte)AsnStatic.ASN_BITSTRING; // asn tag
      v4value[1] = (byte)((1 + j) & 0xFF); // length
      if (ub == 0) {
	v4value[2] = 0x0;
      } else {
	v4value[2] = (byte)(unusedBit & 7);
      }
      for (i = 0; i < j; i++) {
	v4value[3+i] = (byte)(v4number[i] & 0xFF); 
	//System.out.println("v4 " + Integer.toHexString(v4value[i+3] & 0xFF));
      }
      //for (i = 0; i < num+3; i++) {
      //System.out.print(Integer.toHexString(v4value[i] & 0xFF) + " ");
      //}
      //System.out.println("");
      return v4value;
    } else { // v6  2001:0:2/48 ->bit size 0 0x200100000002
      // I guess v6 is hex number, so I need to turn it into decimal first
      j = v6hex.length - (unusedBit / 8);
      v6value[0] = (byte)AsnStatic.ASN_BITSTRING; 
      v6value[1] = (byte)((1 + j) & 0xFF);
      if (ub == 0) {
	v6value[2] = 0x0;
      } else {
	v6value[2] = (byte)(unusedBit & 0x7);
      }
      for (i = 0; i < j; i++) {
	v6value[3+i] = (byte)(Integer.parseInt(v6hex[i], 16) & 0xFF); 
      }
      //for (i = 0; i < v6hex.length + 3; i++) {
      //System.out.print(Integer.toHexString(v6value[i] & 0xFF) + " ");
      //}
      //System.out.println("");
      return v6value;

    }
  }

  private byte[] getLow(String str, String separator) {
    int i = str.indexOf("-");
    byte[] value;

    if (i > 0) { //Ranges
      str = str.substring(0, i).trim();
    } // only one value
    //System.out.println(" Low: " + str );
    value = getBitString(str, separator);
    return value;
  }

  private byte[] getHigh(String str, String separator) {
    byte[] high;

    int i = str.indexOf("-");
    if (i >= 0) {
      str = str.substring(i+1).trim();
      //System.out.println(" High: " + str);
      high = getBitString(str, separator);
    } // only one value
    else {
      high = new byte[1];
      high[0] = 0;
    }
    return high;
  }

  private void addAddress(Ranges ranges, 
			  int index, 
			  String addr, 
			  int type) {
    byte[]  lowB, highB;
    String separator;

    if (type == RuleEditorData.IPV4) {
      separator = ".";
    } else { // v6
      separator = ":";
    }
    lowB = getLow(addr, separator);
    highB = getHigh(addr, separator);
    if (highB[0] == 0) 
      highB = lowB;
    ranges.range.index(index).insert();
    Range r = ranges.range.index(index);
    AsnByteArray b = new AsnByteArray(lowB, lowB[1]+2);
    r.lo.bits.decode(b, lowB[1]+2); 
    b = new AsnByteArray(highB, highB[1]+2);
    r.hi.bits.decode(b, highB[1]+2);
    if (type == RuleEditorData.IPV4) {
      r.maxsiz.write(0x04); // v4 has 32 bits long, as 4 decimal numbers 
      // (0 -255), separated by .
    } else {
      r.maxsiz.write(0x10); //v6 has 128 bits long, as 8 hexadecimal quantities
      // separated by :.
    }

  }

  private int addList(int type,
		       IPPane pane,
		       String[] tmp, 
		       Rule p, 
		       Members m, 
		       int ind) {
    int safi, oldSafi = -1;
    int inda = -1;
    int st;
    boolean newOne = false, inherit = false;
    String addr;
    SpecialRule s = null;

    for (int i = 0; i < tmp.length; i++) {
      // definer rule
      safi = Integer.parseInt(ipv4Pane.getSAFINum(tmp[i]));
      newOne = false;
      if (safi != oldSafi) { // new SAFI
	p.targets.allow.target.index(++ind).insert(); 
	Target t = p.targets.allow.target.index(ind);
	byte[] value = new byte[3];
	// address family is 2 byte long.  Yet we only used
	// the second byte to hold 1 (v4) or 2 (v6). 
	// so the first byte is always 0 for now.
	value[0] = 0; 
	value[1] = (byte)type;
	value[2] = (byte)(safi & 0xFF);
        int j = (safi > 0)? 3: 2;  // STK says we can skip SAFI completely
                    // used to have for v4, so j = (safi > 0)?3 :2;
	AsnByteArray b = new AsnByteArray(value, j);
	t.range.lo.left.write(b, 2);
	t.range.hi.left.write(b, j);
	t.range.maxsiz.write(j);
	oldSafi = safi;
	newOne = true;
	inherit = false; //default
      } 	// if SAFI duplicate, just add to seq of address range
	
      if (newOne) { // Add new safi fields
	// definedBy
	m.member.index(ind).insert();
	Member m1 = (Member)m.member.index(ind);
	inda = -1; // reinitialize for new safi
	if ((st = pane.hasInherit(tmp[i])) == RuleEditorData.REQUIRE_NUM) {
	  inherit = true;
	  m1.name.write("inherit");
	  m1.tagtype.write(AsnStatic.ASN_NULL);
	  // add boolean field
	} else if (st == RuleEditorData.PROHIBIT_NUM) { // add address header
	  inherit = false;
	  m1.name.write("addressOrRanges");
	  m1.tagtype.write(AsnStatic.ASN_SEQUENCE);
	  m1.rule.add();
	  //special rule
	  s = m1.rule.ref.special;
	  s.type.write(0x08); // id_addrRanges
	  addr = pane.getAddrSubstring(tmp[i]);
	  addAddress(s.value.addrRanges, ++inda, addr, type); 
	} else { // RuleEditorData.ALLOW_NUM should be a choice
	  inherit = false; // so address can be added later on
	  m1.rule.add();
	  m1.rule.ref.choice.member.index(0).insert();
	  Member m11 = m1.rule.ref.choice.member.index(0);
	  m11.name.write("inherit");
	  m11.tagtype.write(AsnStatic.ASN_NULL); //0x

	  m1.rule.ref.choice.member.index(1).insert();
	  Member m12 = m1.rule.ref.choice.member.index(1);
	  m12.name.write("addressOrRanges");
	  m12.tagtype.write(AsnStatic.ASN_SEQUENCE);
	  m12.rule.add();
	  //special rule
	  s = m12.rule.ref.special;
	  s.type.write(0x08); // id_addrRanges
	  addr = pane.getAddrSubstring(tmp[i]);
	  addAddress(s.value.addrRanges, ++inda, addr, type); 
	}
      } else { // Add address as seq of this new SAFI entry
	if (!inherit) {
	  addr = pane.getAddrSubstring(tmp[i]);
	  addAddress(s.value.addrRanges, ++inda, addr, type); 
	} // inheirt don't do anything
      }

    }

    return ind;
  }


  public int createRule(Member m) {
    String low, high; 
    int i;
    int ind = -1;
    String[] tmp4 = ipv4Pane.getList();;
    String[] tmp6 = ipv6Pane.getList();
    String addr;
    Target t;
    //SpecialRule s = null;

    if (tmp4.length == 0 && tmp6.length == 0) {
      int ans = JOptionPane.showConfirmDialog(frame,
				    "The IP Address Block extension appears to be empty."
				    + "\nAre you sure you retrieved the correct CA certificate?"
				    + "\nAre you sure you want to do this?"); 
	if (ans == JOptionPane.YES_OPTION) {
	  // continue
	  return RuleEditorData.OK; // OK to have no IP Address Block
	} else if (ans == JOptionPane.NO_OPTION || ans == JOptionPane.CANCEL_OPTION ) {
	  JOptionPane.showMessageDialog(frame, "Please fix the \"IP Address Block\" error."); 
	  return RuleEditorData.FAILED;
	} 
    }

    m.name.write("IP Address Block");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
    SetSeqOfRule sso = (SetSeqOfRule)m.rule.ref.seqOf; //23
    sso.member.name.write("IP Address Family");
    sso.member.tagtype.write(AsnStatic.ASN_SEQUENCE);
    sso.member.rule.add();
    RuleChoice rc = sso.member.rule.ref;

    //definerSeq 22
    rc.definerSeq.members.member.index(0).insert();
    Member m1 = (Member)rc.definerSeq.members.member.index(0);
    m1.name.write("Address Family");
    m1.tagtype.write(AsnStatic.ASN_OCTETSTRING); //0x04
    m1.rule.add();

    //definerRule 28  for safi & ip v4 or v6
    Rule p = (Rule)m1.rule.ref.definerRule;// Rule 


    // definedBy 26 for address
    rc.definerSeq.members.member.index(1).insert();
    Member m2 = (Member)rc.definerSeq.members.member.index(1);
    m2.name.write("IP Address Choice");
    m2.rule.add();
    Members m21 = (Members)m2.rule.ref.definedBy;// CompoundRule 26

    ind = addList(RuleEditorData.IPV4, ipv4Pane, tmp4, p, m21, ind); // add v4
    ind = addList(RuleEditorData.IPV6, ipv6Pane, tmp6, p, m21, ind); // add v6

    return RuleEditorData.SUCCESS;

  }

  private String formStrWithAddress(Ranges ranges,
				    int index,
				    int safiNum,
				    int inheritChoice, //allow or prohibit
				    int type /*v4 or v6 */) {
    AsnByteArray lo = new AsnByteArray();
    AsnByteArray hi = new AsnByteArray();
		   
    Range r = ranges.range.index(index);
    r.lo.bits.encode(lo);
    r.hi.bits.encode(hi);
    //System.out.println("Print encoded address"); // correct one
    //lo.print();
    //hi.print();
    String str = RuleUtils.formAddressString(safiNum, lo, hi, inheritChoice, type); 
    return str;
  }

  public void resetListFromCA()
  {
    if (RuleUtils.cert == null)
	return;  
    v4List = RuleUtils.cert.getV4List();
    v6List = RuleUtils.cert.getV6List();
    ipv4Pane.setBaseList(v4List);
    ipv6Pane.setBaseList(v6List);
    //System.out.println("new v4,v6 lists");
    //printValues(v4List);
    //printValues(v6List);
    //reRendering(RuleUtils.cert.getV4List(), RuleEditorData.IPV4);
    //reRendering(RuleUtils.cert.getV6List(), RuleEditorData.IPV6);
  }


  private boolean setListFromRule(int n4,
			 int n6,
			 Vector data) {
    String[] v4 = new String[n4];
    String[] v6 = new String[n6];

    //System.out.println("in rendering");

    for (int i = 0; i < n4; i++) 
      {
      v4[i] = (String)data.elementAt(i);
      //System.out.println(" v4: " + v4[i]);
      }
    for (int i = n4; i < (n4 + n6); i++) 
      {
      v6[i-n4] = (String)data.elementAt(i);
      //System.out.println(" v6: " + v6[i-n4]);
      }

    //check the v4 and v6 lists to make sure that each 
    // element in them is in the CA list
    String[] caList4 = RuleUtils.cert.getV4List();
    String[] caList6 = RuleUtils.cert.getV6List();
    if (RuleUtils.isASubsetB(v4, caList4) && RuleUtils.isASubsetB(v6, caList6))
    {
	// the base list (origList) is used for restore and 
	// should contain the contents of the CA certificate
	ipv4Pane.setList(v4); // set list contents, not base list
	ipv6Pane.setList(v6); // set list contents, but not base list 
	return true;
    }
    System.out.println("Error in IP Address rule.");
    return false;
  }

  private boolean readListFromRule(IPPane pane,
		       Rule p, 
		       Members m) {
    int safi, type = 0, i, j;
    int nr, n4 = 0, n6 = 0;
    boolean inherit;
    AsnByteArray aba = new AsnByteArray();
    AsnIntRef tagRef = new AsnIntRef();
    Vector data = new Vector();
    String str = new String();
    SpecialRule s = null;

    int ni = p.targets.allow.numitems();
    for (i = 0; i < ni; i++) 
      {
      // read type and safe info
      Target t = p.targets.allow.target.index(i);
      AsnByteArray b = new AsnByteArray(3);
      t.range.lo.left.read(b);
      //t.range.hi.left.read(b);
      byte[] value = b.getArray();
      type = value[1];
      safi = value[2];
      
      // read adddress info
      Member m1 = (Member)m.member.index(i);
      if (m1.rule.ref == null) 
        { // inherit require
	inherit = true;
	str = "SAFI " +  safi + "\t \t INHERIT";
	//System.out.println(" V " + type + " str: " + str);
	data.add(str);
	switch (type) 
          {
	case RuleEditorData.IPV4: n4++; break;
	case RuleEditorData.IPV6: n6++; break;
          }
        } 
      else 
         { // inherit allow or prohibit
         inherit = false;
         }
      if (inherit == false) { // inherit allow or prohibit
	m1.rule.ref.tag(tagRef);
	switch(tagRef.val) 
          {
	case 0xE5: //choice, inherit allow
	  Member m12 = m1.rule.ref.choice.member.index(1);
	  //special rule
	  s = m12.rule.ref.special;
	  nr = s.value.addrRanges.numitems();
	  for (j = 0; j < nr; j++) 
            {
	    str = formStrWithAddress(s.value.addrRanges, j, safi, RuleEditorData.ALLOW_NUM, type);
	    data.addElement(str);
	    switch (type) 
              {
	    case RuleEditorData.IPV4: n4++; break;
	    case RuleEditorData.IPV6: n6++; break;
	      }
	    }
	  break;
	case 0xED: //special, inherit prohibit
	  s = m1.rule.ref.special;
	  nr = s.value.addrRanges.numitems();
	  for (j = 0; j < nr; j++) 
            {
	    str = formStrWithAddress(s.value.addrRanges, j, safi, RuleEditorData.PROHIBIT_NUM, type);
	    data.addElement(str);
	    switch (type) 
              {
	    case RuleEditorData.IPV4: n4++; break;
	    case RuleEditorData.IPV6: n6++; break;
	      }
	    }
	  break;
	}
      }
    }
    return setListFromRule(n4, n6, data);
  }

  public boolean setRule(Member m) {
    SetSeqOfRule sso = m.rule.ref.seqOf; //23
    Member m1 = sso.member.rule.ref.definerSeq.members.member.index(0);
    Rule p = m1.rule.ref.definerRule;// Rule 
    Member m2 = sso.member.rule.ref.definerSeq.members.member.index(1);
    Members m21 = m2.rule.ref.definedBy;// CompoundRule 26

    return readListFromRule(ipv4Pane, p, m21);


  }
  
}
