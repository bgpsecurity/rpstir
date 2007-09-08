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
import skaction.*;
import Algorithms.*;
import name.*;
import certificate.*;
import extensions.*;

import java.util.*;
import java.io.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class RuleUtils{
  private static JFrame frame;
  public static JFrame ruleFrame;
//  private static Xmodem xmodem;
  public static String CAfilename = null;
  public static RenderCA cert = null;
  public static String RootDir = "../certs";
  final static JFileChooser fc2 = new JFileChooser(RootDir); 

  public RuleUtils() {
  }

  static boolean isDigit(String s) {
    boolean isNumber = true;

    for (int i = 0; !isNumber && i < s.length(); i++) {
      if (!Character.isDigit(s.charAt(i))) {
        isNumber = false;
      }
    }
    return isNumber;    
  }

  static JPanel getInnerPane(String name) {
    JLabel label = new JLabel(name, JLabel.CENTER);
    label.setFont(new java.awt.Font("Dialog", 1, 12));
    JPanel innerPane = new JPanel();
    innerPane.add(label);
    innerPane.setBorder(new EmptyBorder(20, 10, 20, 10));

    return innerPane;
  }

  static IssuerName getIssuerNameFromRDNS(RDNSequence rdns) {
    IssuerName isName = new IssuerName();

    int n = rdns.numitems();
    isName.setItemNum(n);
    for (int i = 0; i < n; i++) {
      //String DNID = null, DNname = null, DNvalue = null;
      RelativeDistinguishedName rdn = rdns.relativeDistinguishedName.index(i);
      int size = rdn.attributeValueAssertion.index(0).objid.vsize();
      AsnByteArray tmp = new AsnByteArray(size);
      rdn.attributeValueAssertion.index(0).objid.read(tmp);
      //System.out.println(" obj id: " );
      //tmp.print();
      String DNID = tmp.toString();
      //System.out.println(" DNID: " + DNID);
      String DNname = getObjIDname(DNID.trim());
      //System.out.println(" DNname: " + DNname);
      size = rdn.attributeValueAssertion.index(0).value.vsize();
      tmp = new AsnByteArray(size);
      rdn.attributeValueAssertion.index(0).value.read(tmp);
      //tmp.print();
      String DNvalue = tmp.toString();
      //System.out.println(" Value: " + DNvalue);
      isName.setItem(i, DNname, DNvalue);
    }
    
    return isName;
  }

    /**
       isASubsetB returns true if each element of A appears
       in B and false otherwise
     **/
  static boolean isASubsetB(String [] listA, String[] listB)
  {
      if (listB == null) 
	  return false;
      if (listA == null)
	  return true;
      //System.out.println("in isASubsetB");
      for(int i=0; i< listA.length; i++)
      {
	  if (!findElement(listB, listA[i]))
	      return false;
      }
      return true;
  }

    /**
       findElement returns true if toFind is an element of listA
       and false otherwise
    **/
    static boolean findElement(String[] listA, String toFind)
    {
	if (listA == null)
	    return false;
	//System.out.println("findElement, looking for " + toFind);
	toFind = toFind.trim();
	for (int i=0; i< listA.length; i++)
	{
	    if (listA[i].compareTo(toFind) == 0)
	    {
		//System.out.println("found element");
		return true;
	    }
	}
	return false;
    }

  static String correct2fit(String tmp)
  {
    String str = tmp;

    if (str.length() == 1) { // Add leading 0
      str = new String("0" + tmp);
    }

    return str;
  }

    /**
       returns a string representing the address in lo with the specified type
       valid values for type are RuleEditorData.IPV4 and RuleEditorData.IPV6
    **/
  static String formAddress(byte[] lo, int type) 
    {
    String str = null;
    String tmp = null;
    String tmp1 = null;
    int unUsed = lo[2] & 0xFF; // unused bits
    int used = 0;
    int max = 0;
    int n = (lo[1] & 0xFF) + 2; // length
    int start;
    int zeros = 0;

    if (type == RuleEditorData.IPV4) 
	start = 3;
    else start = 4; // v6 first address ends in byte 4
   
    for (int i = 3; i < n; i++) 
      {
      if (type == RuleEditorData.IPV4) tmp = Integer.toString((lo[i] & 0xFF));
      else 
      { // type = 6
        tmp = correct2fit(Integer.toString((lo[i] & 0xFF), 16));
        if (++i == n) tmp1 = "00";
        else tmp1 = correct2fit(Integer.toString((lo[i] & 0xFF), 16));
        tmp = new String(tmp + tmp1);
        if (tmp.equals("0000")) 
          {
          zeros++;
          if (zeros == 2) 
            { // trimmed down 0000 -> null
            byte[] t = str.getBytes();
            str = new String(t, 0, t.length - 4);
            }
          } 
        else zeros = 0;
      }
      if (i == start) 
	  str = new String(tmp);   // first address
      else if (type == RuleEditorData.IPV4) 
	  str = new String(str + "." + tmp);
      else if (zeros <= 1) 
	  str = new String(str + ":" + tmp);
      }
   
    if (type == RuleEditorData.IPV4) max = 4 + 3;
    else max = 8 * 2 + 3;
    
    if (n != max) 
      { // not full address, need used bit count
      if (n >= 3) used = (n - 3) * 8 - unUsed;
      else 
        {
        used = 0;
        str = new String("0");
        }
      tmp = Integer.toString(used);
      str = new String(str + "/" + tmp);
      }

    //System.out.println(" address str: " + str);
    return str;
  }



  public static String formAddressString(int safiNum,
        		   AsnByteArray lo, 
        		   AsnByteArray hi,
        		   int inheritChoice,
        		   int type) { //allow or prohibit
    String str = new String("SAFI " + safiNum + "\t ");
    String tmp = null;
    byte[] loB = lo.getArray();
    byte[] hiB = hi.getArray();

    tmp = formAddress(loB, type);
    //lo.print();
    //hi.print();
    str = new String(str + tmp);
    if (!hi.equals(lo)) { // need to get hi address
      tmp = formAddress(hiB, type);
      str = new String(str + " - " + tmp);
    }
    
    if (inheritChoice == RuleEditorData.ALLOW_NUM) { // add inherit
      str = new String(str + " \t INHERIT");
    } 
    //System.out.println(" whole address str: " + str);
    return str;
  }
  
  static int addRuleMember(FieldBasePane o, RuleChoice rc, int index, String msg) {
    int good;
    int lth;
    AsnByteArray out = new AsnByteArray(500);
  //     System.out.println("Adding " + msg + " index " + index); 
    rc.sequence.members.member.index(index).insert();
    Member m = (Member)rc.sequence.members.member.index(index);
    good = o.createRule(m);
    switch(good) 
      {
    case RuleEditorData.FAILED:       
      rc = null;
      break;
    case RuleEditorData.OK:
      rc.sequence.members.member.index(index).remove();
      break;
    case RuleEditorData.SUCCESS:
      if ((lth = rc.size()) < 0) 
        { //In real production this should not happen
        //System.out.println(
        //   " addRuleMember size out = " + lth + " " + AsnErrorMap.asn_map_string);
          good = RuleEditorData.FAILED;
          rc = null;
        } 
      else 
        { 
        //rc.put_file(msg + ".req");
        //System.out.println(" **** Done print upto " + msg);
        }
      break;
    default:
       JOptionPane.showMessageDialog(frame, "Invalid choices in RuleUtils.addRuleMember rule set"); 
        return -1; 
    }
    return good;
  }

  static int getOidIndex(String name[], String OID) {
    OID = OID.trim();
    for (int i = 0; i < name.length; i++) {
      if (name[i].equals(OID)) {
          //System.out.println(" i: " + i + " " + name[i] + " " + OID);
        return i;
      }
    }

    return -1;

  } 
  
  static int getNameIndex(String names[], String name) {
    return(getOidIndex(names, name));
 
  } 
  
  static String getNameObjID(String name) {
    String objId = new String();

      if (name.equals(RuleEditorData.COMMON_NAME)) {
        objId = NameStatic.id_commonName;
      } else if (name.equals(RuleEditorData.COUNTRY_NAME)) {
        objId = NameStatic.id_countryName;
      } else if (name.equals(RuleEditorData.ORG_NAME)) {
        objId = NameStatic.id_organizationName;
      } else if (name.equals(RuleEditorData.ORG_UNIT_NAME)) {
        objId = NameStatic.id_organizationalUnitName;
      } else if (name.equals("Locality Name")) {
        objId = NameStatic.id_localityName;
      } else if (name.equals("State Or Province Name")) {
        objId = NameStatic.id_stateOrProvinceName;
      } else if (name.equals("Surname")) {
        objId = NameStatic.id_surname;
      } else if (name.equals("Given Name")) {
        objId = NameStatic.id_givenName; 
      } else if (name.equals("Initials")) {
        objId = NameStatic.id_initials; 
      } else if (name.equals("Generation Qualifier")) {
        objId = NameStatic.id_generationQualifier; 
      } else if (name.equals("Email Address")) {
        objId = NameStatic.id_emailAddress;
      } else if (name.equals("Serial Number")) {
        objId = NameStatic.id_serialNumber;
      } else if (name.equals("Domain Component")) {
        objId = NameStatic.id_at_dc;
      }

      return objId;
  }

  static String getObjIDname(String objId) {
    String name = new String();

      objId = objId.trim();
      if (objId.equals(NameStatic.id_commonName)) {
        name = RuleEditorData.COMMON_NAME;
      } else if (objId.equals(NameStatic.id_countryName)) {
        name = RuleEditorData.COUNTRY_NAME;
      } else if (objId.equals(NameStatic.id_localityName)) {
        name = "Locality Name";
      } else if (objId.equals(NameStatic.id_stateOrProvinceName)) {
        name = "State Or Province Name";
      } else if (objId.equals(NameStatic.id_organizationName)) {
        name = RuleEditorData.ORG_NAME;
      } else if (objId.equals(NameStatic.id_organizationalUnitName)) {
        name = RuleEditorData.ORG_UNIT_NAME;
      } else if (objId.equals(NameStatic.id_surname)) {
        name = "Surname";
      } else if (objId.equals(NameStatic.id_givenName)) {
        name = "Given Name"; 
      } else if (objId.equals(NameStatic.id_initials)) {
        name = "Initials"; 
      } else if (objId.equals(NameStatic.id_generationQualifier)) {
        name = "Generation Qualifier"; 
      } else if (objId.equals(NameStatic.id_emailAddress)) {
        name = "Email Address";
      } else if (objId.equals(NameStatic.id_serialNumber)) {
        name = "Serial Number";
      } else if (objId.equals(NameStatic.id_at_dc)) {
        name = "Domain Component";
      }

      return name;
  }

  static String getDNufn(String name) { // user friendly name
    String attrName = new String();

      if (name.equals("Common Name")) {
        attrName = "CN";
      } else if (name.equals("Country Name")) {
        attrName = "C";
      } else if (name.equals("Locality Name")) {
        attrName = "L";
      } else if (name.equals("State Or Province Name")) {
        attrName = "ST";
      } else if (name.equals("Organization Name")) {
        attrName = "O";
      } else if (name.equals("Organization Unit Name")) {
        attrName = "OU";
      } else if (name.equals("User ID")) {
        attrName = "UID"; //??
      } else if (name.equals("Domain Component")) {
        attrName = "DC";
      }

      return attrName;
  }

  static boolean goodDNattr(String dn) {
    if (dn.equalsIgnoreCase("DC") ||
        dn.equalsIgnoreCase("CN") || 
        dn.equalsIgnoreCase("C") || 
        dn.equalsIgnoreCase("L") || 
        dn.equalsIgnoreCase("ST") || 
        dn.equalsIgnoreCase("O") || 
        dn.equalsIgnoreCase("OU") || 
        dn.equalsIgnoreCase("UID") ) {
        return true;
    } else {
        return false;
    }
  }
    
  static String getUfnDN(String name) { // user friendly name
    String attrName = new String();

      if (name.equalsIgnoreCase("CN")) {
        attrName = "Common Name";
      } else if (name.equalsIgnoreCase("C")) {
        attrName = "Country Name";
      } else if (name.equalsIgnoreCase("L")) {
        attrName = "Locality Name";
      } else if (name.equalsIgnoreCase("ST")) {
        attrName = "State Or Province Name";
      } else if (name.equalsIgnoreCase("O")) {
        attrName = "Organization Name";
      } else if (name.equalsIgnoreCase("OU")) {
        attrName = "Organization Unit Name";
      } else if (name.equalsIgnoreCase("UID")) {
        attrName = "User ID"; 
      } else if (name.equalsIgnoreCase("DC")) {
        attrName = "Domain Component";
      }

      return attrName;
  }


  static String dnContent2ufn(AsnByteArray aba) {
    //System.out.print(" In dncontent2ufn");
    //aba.print();
    //Name name = new Name();
    RDNSequence rdns  = new RDNSequence();
    aba.resetPtr();
    rdns.write(aba);
    //System.out.print(" done rdns.write()");
    rdns.encode(aba);
    //aba.print();
    return dn2ufn(aba);
  }

  static String dn2ufn(AsnByteArray aba) {
    //System.out.println("in dn2ufn");
    String ufn = new String();
    Name name = new Name();
    
    //aba.print();
    aba.resetPtr();
    int ansr = name.decode(aba);
    //System.out.println("name.decode(): " + ansr);
    RDNSequence rdns = name.rDNSequence;
    IssuerName subjName = RuleUtils.getIssuerNameFromRDNS(rdns); 
    ufn = subjName.getUfn();
    return ufn;
  }

  static AsnByteArray ufn2dnContent(String ufn) {
    AsnByteArray aba = new AsnByteArray();

    //System.out.println("ufn2dnContent");
    aba = ufn2dn(ufn);
    Name name = new Name();
    name.decode(aba);
    int lth = name.vsize();
    aba = new AsnByteArray(lth);
    name.read(aba); //read the naem contents. read() leaves pointer at the end
    aba.resetPtr(); // we need to resetPtr to beginning
    //System.out.print("\n#### name content: ");
    //aba.print();
    return aba;
  }

  /*static String ufn2dn(String ufn) {
    AsnByteArray aba = new AsnByteArray();
    ufn2dn(ufn, aba);
    String dn = new String(aba.toString());

    return dn;
    }*/

  static AsnByteArray ufn2dn(String ufn) {
    AsnByteArray aba = new AsnByteArray();
    String attr, value;
    int ni, i, indS = 0, indE, ind = 0;

    Name name = new Name();
    RDNSequence rdns = name.rDNSequence;
    ufn = ufn.trim();

    //System.out.println("ufn: " + ufn);
    if (ufn.endsWith(",")) {
      //System.out.println(" ufn ends with ,: " + ufn);
      int lth = ufn.length();
      ufn = ufn.substring(0, lth - 1);
      //System.out.println(" ufn trim ,: " + ufn);
    }
    StringTokenizer st = new StringTokenizer(ufn, ",");
    ni = st.countTokens();
    String[] ufns = new String[ni];
    i = ni;
    while (st.hasMoreTokens()) {
      ufns[--i] = st.nextToken().trim();
    }
    for (i = 0; i < ni; i++) {
        //String token = st.nextToken().trim();
      StringTokenizer sts = new StringTokenizer(ufns[i], "=");
      String attrUfn = sts.nextToken().trim();
      attr = getUfnDN(attrUfn);
      value = sts.nextToken().trim();
      makeRdn(rdns, ind++, attr, value);
      //System.out.println("attr: " + attr + ", value: " + value);
    }
    name.encode(aba);
    //name.read(aba);
    //System.out.print("\n#### name : ");
    //aba.print();
    return aba;
  }

  static void makeRdn(RDNSequence rdns, int ind, String attr, String value) {
    AsnByteArray aba = new AsnByteArray();
 
    //byte[] name = new byte[50];
    String id = getNameObjID(attr);
    rdns.relativeDistinguishedName.index(ind).insert();
    RelativeDistinguishedName rdn = rdns.relativeDistinguishedName.index(ind);
    rdn.attributeValueAssertion.index(0).insert();
    AttributeValueAssertion attrVal = rdn.attributeValueAssertion.index(0); 
    
    attrVal.objid.write(id);
    attrVal.value.write(value);
    rdn.encode(aba);
    //System.out.print("\n*** rdn : ");
    //aba.print();
  }

  static void ufn2rdn(RelativeDistinguishedName rdn, String ufn) {
    int index = -1;
    int i, ni;

    //System.out.println("ufn2rdn ufn: " + ufn + ".");
    if (ufn.endsWith(",")) {
      int lth = ufn.length();
      ufn = ufn.substring(0, lth - 1);
      //System.out.println(" ufn trim ,: " + ufn);
    }
    StringTokenizer st = new StringTokenizer(ufn, ",");
    ni = st.countTokens();
    String[] ufns = new String[ni];
    i = ni;
    while (st.hasMoreTokens()) {
        ufns[--i] = st.nextToken().trim();;
    }

    for (i = 0; i < ni; i++) {
        //String token = st.nextToken().trim();
      StringTokenizer sts = new StringTokenizer(ufns[i], "=");
      String attrUfn = sts.nextToken().trim();
      String attr = getUfnDN(attrUfn);
      String id = getNameObjID(attr);
      String value = sts.nextToken().trim();
      //System.out.println(" attr: " + attr + " value: " + value);
      rdn.attributeValueAssertion.index(++index).insert();
      AttributeValueAssertion attrVal = rdn.attributeValueAssertion.index(index); 
      attrVal.objid.write(id);
      attrVal.value.write(value);
    }

  }

  static AsnByteArray ufn2rdn(String ufn) {    
    RelativeDistinguishedName rdn = new RelativeDistinguishedName();
    ufn2rdn(rdn, ufn.trim());
    int n = rdn.vsize();
    //System.out.println(" rdn size: " + n);
    AsnByteArray aba = new AsnByteArray(n);
    rdn.read(aba);
    //System.out.print("\n*** rdn : ");
    //aba.print();

    return aba;
  }

  static void rdn2Rule(Targets ts, String[] ufn) {
    //System.out.println("rdnRule. ufn count: " + ufn.length);
    for (int i = 0; i < ufn.length; i++) {
      //System.out.println("  ufn: " + ufn[i]);
      ts.target.index(i).insert();
      Target t = ts.target.index(i);
      AsnByteArray aba = ufn2rdn(ufn[i].trim());
      //System.out.print("\n#### ufn2dn : ");
      //aba.print();
      aba.resetPtr();
      t.value.write(aba);
    }
  }


  static String getGeneralNameType(String text) {
    if (text.equals("directory") || text.indexOf("=") >= 0) {
      return("Directory Name");
    }  else if (text.equals("rfc822") || text.indexOf("@") >= 0) {
      return ("rfc822 Name");
    } else if (text.indexOf("-") > 0) {
      return ("IP Address");
    } else {
      if (text.indexOf(".") > 0) {
        boolean digit = true;
        StringTokenizer st = new StringTokenizer(text, ".");
        while (st.hasMoreTokens()) {
          String tmp = st.nextToken().trim();
          for (int i = 0; digit && i < tmp.length(); i++) {
            if (!Character.isDigit(tmp.charAt(i))) {
              digit = false;
            }
          }
          if (digit) {
            return("IP Address");
          } else {
            return ("rfc822 Name");
          }
        }
      } else {
        return ("rfc822 Name");
      }
    }
      
    return(" ");
  } 

  static boolean inList(String name, String[] allName) {
    for (int i = 0; i < allName.length; i++) {
      if (name.equals(allName[i])) {
        return true;
      }
    }
    return false;
  }

  static int getV4number(String str, int[] number) {
    int num = -1;
    int start = 0, end = 0;
    boolean stop = false;

    while (!stop) {
      end = str.indexOf(".", start);
      if (end < 0) {
        stop = true;
        end = str.length();
      }
      
      number[++num] = Integer.parseInt(str.substring(start, end).trim()) ;
      //System.out.println("v4 number("+ num + "): " + number[num]); 
      start = end + 1;
    }

    return(++num);
  }

    static String getTabType(int type)
    {
	if (type == SkactionStatic.id_alt2_type)
	    return RuleEditorData.EE_TYPE;
	else if (type == SkactionStatic.id_alt3_type)
	    return RuleEditorData.CA_TYPE;
	else 
	    return RuleEditorData.CRL_TYPE;
    }

  static int getRuleType(String type) {
    if (type.equals(RuleEditorData.EE_TYPE)) {
      return SkactionStatic.id_alt2_type;
    } else if (type.equals(RuleEditorData.CA_TYPE)) {
      return SkactionStatic.id_alt3_type;
    } else if (type.equals(RuleEditorData.CRL_TYPE)) {
      return 8;
    }

    return -1;
  }

  public static String getSaveFilename()
  {
      File file;
      String fileName;
      JFileChooser fc = new JFileChooser(RuleUtils.RootDir);
      int returnVal = fc.showDialog(null, "Save Rule File");
      
      if (returnVal == JFileChooser.APPROVE_OPTION) 
      {
        file = fc.getSelectedFile();
        fileName = file.getAbsolutePath();
        System.out.println("  file: " + fileName);

        File ff = new File(fileName); 
        if (ff.exists()) 
        {
          int n = JOptionPane.showConfirmDialog(null,
        	"You are about to overwrite an existing file. "
		 + "Are you sure you want to do this?", "Confirm Override",
				    JOptionPane.YES_NO_OPTION);
          if (n == JOptionPane.NO_OPTION) 
            {
              JOptionPane.showMessageDialog(null, 
                "Create rule cancelled by the user."); 
              return null;
            } 
	}
	return ff.getAbsolutePath();
      }
      else  
      {
        JOptionPane.showMessageDialog(null, 
            "Create rule cancelled by the user.",
	    "Cancelled command", JOptionPane.INFORMATION_MESSAGE); 
	return null;
      }
  }

  static void formNsendSKrequest(String type, AsnByteArray buf, int lth, String keyName, String fileName) {
    String objId;
    
    RulePackage rp = new RulePackage();
    Name name = rp.ca;
    RDNSequence rdns = name.rDNSequence;
    int n = cert.getIssuerName().getItemNum();
    for (int i = 0; i < n; i++) {
      rdns.relativeDistinguishedName.index(i).insert();
      RelativeDistinguishedName rdn = rdns.relativeDistinguishedName.index(i);
      rdn.attributeValueAssertion.index(0).insert(); //AttributeValueAssertion
      // get objID
      rdn.attributeValueAssertion.index(0).objid.write(getNameObjID(cert.getIssuerName().getDNname(i)));
      rdn.attributeValueAssertion.index(0).value.write(cert.getIssuerName().getDNvalue(i));
    }
    //rp.ca = name; // name
    rp.keyName.write(keyName); 
    rp.nonce.write((int)(System.currentTimeMillis()/1000)); //genenralize time
    rp.ruleSets.ruleSet.index(0).insert();
    RuleSet rs = rp.ruleSets.ruleSet.index(0);
    int ruleType = getRuleType(type);
    rs.type.write(ruleType);
    rs.ruleGroup.fileData.index(0).insert();
    FileData fd = rs.ruleGroup.fileData.index(0);
    if (fileName == null)
	fileName = getSaveFilename();
    if (fileName == null)
	return;
    fd.name.write(fileName);
    fd.contents.decode(buf);

    //lth = rp.size();
    AsnByteArray out = new AsnByteArray(lth + 100);
    if ((lth = rp.encode(out)) < 0) {
	//System.out.println("rp encode out = " + lth + " " + AsnErrorMap.asn_map_string);
      JOptionPane.showMessageDialog(frame, "rp encode error: " + lth + " " + AsnErrorMap.asn_map_string);
      return;
    }
    

    SKAction skaction = new SKAction();
    skaction.req.opcode.write(SkactionStatic.id_sign); 
    skaction.req.cmd.sign.keyName.write("rsa"); 
    skaction.req.cmd.sign.hash.write(SkactionStatic.id_SHA1_HASH);
    skaction.req.cmd.sign.pad.write(SkactionStatic.id_none);
    skaction.req.cmd.sign.rules.write(SkactionStatic.id_cert_type);
    skaction.req.cmd.sign.typ.write(SkactionStatic.id_sign_rules);
    lth = skaction.req.cmd.sign.signd.rules.toBeSigned.decode(out);
    //System.out.println("toBeSigned.decode() status: " + lth); 
    skaction.req.cmd.sign.signd.rules.algorithm.algorithm.write(AlgorithmsStatic.id_secsig_SHA_1withRSASignature);
    // parameter is none
    skaction.req.cmd.sign.signd.rules.signature.write("");

    AsnByteArray inBuf = new AsnByteArray(lth+100);

    if ((lth = skaction.encode(inBuf)) < 0) {
      JOptionPane.showMessageDialog(frame, "skaction encode error: " + lth + " " + AsnErrorMap.asn_map_string);
      //System.out.println(" skaction encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    }
    else {
      skaction.put_file(fileName);
      System.out.println(" **** Done print " + fileName);
    }

    // Uncomment the following line to activate SK
    SKCommunication(inBuf.getArray(), lth, fileName + ".resp");
    

  }

  static String getErrorMsg(int errorCode) {

     String[] error0to54 = {
      "No error",
      "Hardware or software processing error",
      "Too many retries receiving request",
      "Invalid ASN.1 encoding",
      "Invalid IAName",
      "Unauthorized transaction request",
      "Invalid certificate",
      "Inconsistent key pair",
      "Message signature failure",
      "Invalid Postage Meter ID",
      "Invalid nonce",
      "Invalid issuer name",
      "Invalid subject name",
      "Invalid serial number",
      "Invalid validity interval",
      "Invalid CRL date",
      "Length field of msg hdr doesn't match length",
      "Unknown hash/encryption algorithm",
      "Memory diagnostic error",
      "Error in EEPROM",
      "Error in PROM",
      "CIK doesn't match active authority",
      "No CIK inserted",
      "New CIK not inserted in time",
      "Error reading or writing CIK",
      "Error reading or writing fill device",
      "No fill device inserted",
      "IASK reuse not authorized",
      "No room in EEPROM",
      "IASC package not available",
      "No active issuing authority ",
      "Serial number out of sequence",
      "No USC present",
      "IAname in iasc package doesn't match request",
      "Invalid IA type",
      "Error in  option(s)",
      "No TLCA control public component",
      "Unknown or wrong version in certificate/CRL",
      "Unknown control message type",
      "Invalid public component structure",
      "Invalid key size",
      "Hash check failed",
      "Number of issuing authorities exceeded 0xFFFF",
      "Error from random number generator",
      "Fill device not cleared",
      "Checksum error in IASC package",
      "Improper DSA parameters P, Q & G",
      "Crypto officer state required",
      "Error in SCSI functions",
      "Error DES en/decrypting",
      "Error in secret-sharing routines",
      "Invalid private component structure",
      "Error on diagnostic on BBRAM",
      "Bad Secret Component",
      "Error from RSADSI routines in range BAD_RSA - BAD_RSA+0x10, i.e. 54 - 70",
    };
    
     final int BAD_SHARE   = 71;    /* invalid threshold/sharecount combination */
     final String BAD_SHARE_MSG   = "invalid threshold/sharecount combination";

    String[] error85to107 = {
      "invalid threshold/sharecount combination",
      "BadSHA1",
      "ExceedTries",
      "BadG", 
      "BadR",  
      "BadS",
      "key name not found or key already exits",
      "BAD_USAGE",
      "BAD_TYPE",
      "DIFF_CIK",
      "CLOCK_ERR",
      "AUDIT_FULL",
      "FLASH_ERR",
      "too many key names",
      "size of file exceeds the requested size",
      "size of backed up name and keys exceeds FILL size",
      "no file of that number",
      "error in rule file",
      "failed regular rule",
      "failed group rule",
      "rule set missing a file",
      "rule set has a loop",
      "file system is full",
      "error writing audit file"
    };
/* warnings */
     final int WARN_ERR    = 0xC0; /* mase system 80% full */
     final int HI_FILESYS  = 0xFA; /* file system 80% full */
     final int VHI_FILESYS = 0xFB; /* "      "    90%  "   */
     final int HI_AUDIT    = 0xFC; /* audit memory 80% full */
     final int VHI_AUDIT   = 0xFD; /* "      "    90%  "   */
     final int LO_BATT     = 0xFE; /* Battery for tamper memory is low */
     final int WARN_EEP    = 0xFF; /* count of EEPROM writes is too high */

     final String WARN_ERR_MSG    = "mask for warnings vs. fatal errors";
     final String HI_FILESYS_MSG  = "file system 80% full";
     final String VHI_FILESYS_MSG = "VHI_FILESYS"; /* "      "    90%  "   */
     final String HI_AUDIT_MSG    = "audit memory 80% full";
     final String VHI_AUDIT_MSG   = "audit memory 90% full";
     final String LO_BATT_MSG     = "Battery for tamper memory is low";
     final String WARN_EEP_MSG    = "count of EEPROM writes is too high";


    if (errorCode >= 0 && errorCode <= 54) {
      return error0to54[errorCode];
    } else if (errorCode >= 85 && errorCode <= 107) {
      System.out.println(" error: " + errorCode);
      return error85to107[errorCode];
    } else if (errorCode == BAD_SHARE) {
      return BAD_SHARE_MSG;
    } else if (errorCode == WARN_ERR) {
      return WARN_ERR_MSG;
    } else if (errorCode == HI_FILESYS) {
      return HI_FILESYS_MSG;
    } else if (errorCode == VHI_FILESYS) {
      return VHI_FILESYS_MSG;
    } else if (errorCode == HI_AUDIT) {
      return HI_AUDIT_MSG;
    } else if (errorCode == VHI_AUDIT) {
      return VHI_AUDIT_MSG;
    } else if (errorCode == LO_BATT) {
      return LO_BATT_MSG;
    } else if (errorCode == WARN_EEP) {
      return WARN_EEP_MSG;
    } else {        	
      return " ";
    }

  }

  static boolean connectSK() {
    /*  Uncomment this block to activate SK  
    xmodem = new Xmodem("RuleEdtior");
    if (!xmodem.open()) {// error in open
      String msg = xmodem.getErrorMsg();
      JOptionPane.showMessageDialog(frame, msg);
      return false;
      } */
    
    return true;
  }

  public static void closeSK() {
    // uncommnet next line to activate SK
    /* xmodem.close();*/
  }

  static void SKCommunication(byte[] buf, 
        		      int lth, 
        		      String fname) {
    FileOutputStream ofile = null;
    
    
  }

  static void formEnterDisplayPane(DefaultListModel listModel,
        			   JList list,
        			   JScrollPane listScrollPane,
        			   JButton addButton,
        			   JButton removeButton,
        			   JPanel inputPane,
        			   String title,
        			   JPanel pane) {
    Dimension dim;

    //Create the list and put it in a scroll pane
    //list = new JList(listModel);
    list.setVisibleRowCount(5);
    list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

    dim = new Dimension(180, 200);
    listScrollPane.setMinimumSize(dim);
    listScrollPane.setPreferredSize(dim);
    listScrollPane.setMinimumSize(dim);
        
    //removeButton = new JButton("Removle");
    //removeButton.setActionCommand(removeString);
    //removeButton.addActionListener(new removeListener());

    //inputPane will be supplied by individual class which used this mehtod

    //Create a panel that houses the input and buttons.
    
    JPanel buttonPane = new JPanel();
    buttonPane.add(addButton);
    buttonPane.add(removeButton);
    
    JPanel inputButtonPane = new JPanel();
    inputButtonPane.setLayout(new BoxLayout(inputButtonPane, BoxLayout.Y_AXIS));
    inputButtonPane.add(inputPane);
    inputButtonPane.add(buttonPane);
    
    pane.setLayout(new BoxLayout(pane, BoxLayout.Y_AXIS));
    pane.add(listScrollPane);
    pane.add(Box.createRigidArea(new Dimension(0,5)));
    pane.add(inputButtonPane); 
    
    pane.setBorder(new TitledBorder(new EtchedBorder(), title));


  }

  static void formDSAAlgorithmRule(Member m211) {
    
    m211.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m211.rule.add();
    m211.rule.ref.sequence.members.member.index(0).insert();
    Member m2110 = m211.rule.ref.sequence.members.member.index(0);
    m2110.tagtype.write(AsnStatic.ASN_INTEGER); // P
    m211.rule.ref.sequence.members.member.index(1).insert();
    Member m2111 = m211.rule.ref.sequence.members.member.index(1);
    m2111.tagtype.write(AsnStatic.ASN_INTEGER); // Q
    m211.rule.ref.sequence.members.member.index(2).insert();
    Member m2112 = m211.rule.ref.sequence.members.member.index(2);
    m2112.tagtype.write(AsnStatic.ASN_INTEGER); // G
  }
  
  
  
  public static void formAlgoRule(RuleChoice rc, 
        			  String msgLeader, 
        			  String[] choice,
        			  String[] name,
        			  String[] oid) {
    int i;
    int index = 0;
    boolean required = false;
    
    //Add definerRule member
    rc.definerSeq.members.member.index(0).insert();
    Member m1 = (Member)rc.definerSeq.members.member.index(0);
    m1.name.write(msgLeader + "Algorithm Value");
    m1.tagtype.write(AsnStatic.ASN_OBJ_ID); //0x06
    m1.rule.add();
    Rule p = (Rule)m1.rule.ref.definerRule;//  28
    
    // get data
    for (i = 0; i < choice.length; i++) {
      if (choice[i].equals(RuleEditorData.REQUIRE)) {
        p.targets.require.target.index(0).insert();
        ((Target)p.targets.require.target.index(0)).objid.write(oid[i]);
        required = true;
        break;
      }
    }
    
    if (!required) {
      index = -1;
      for (i = 0; i < choice.length; i++) {
        if (choice[i].equals(RuleEditorData.ALLOW)) {
          p.targets.allow.target.index(++index).insert();
          ((Target)p.targets.allow.target.index(index)).objid.write(oid[i]);
        }
      }
    }
    
    //Add definedBy member41

    rc.definerSeq.members.member.index(1).insert();
    Member m2 = (Member)rc.definerSeq.members.member.index(1);
    m2.name.write(msgLeader + "Algorithm Parameters");
    //m2.tagtype.write(AsnStatic.ASN_OBJ_ID); //0x06
    m2.rule.add();
    Members m21 = (Members)m2.rule.ref.definedBy;// 26 
    for (i = 0, index = -1; i < choice.length; i++) {
      // Add definedBy parameters
      if (choice[i].equals(RuleEditorData.ALLOW) || 
          choice[i].equals(RuleEditorData.REQUIRE)) {
        m21.member.index(++index).insert();
        Member m211 = (Member)m21.member.index(index);
        
        if (!msgLeader.equals("")) { //Signature Algorithm
          if (name[i].equals("secsig-MD5withRSA:") || 
              name[i].equals("secsig-MD5withRSASignature:") || 
              name[i].equals("secsig-SHA-1withRSASignature:") ||
              name[i].equals("dsa-with-sha1:")) {
            m211.tagtype.write(AsnStatic.ASN_NONE); 
            // No parameter filled	
          } else if (name[i].equals("secsig-DSAwithSHA-1:")) {
            formDSAAlgorithmRule(m211);
                // CWG deleted colons in next 2 to make it work
          } else if (name[i].equals("rsadsi-sha-1WithRSAEncryption") ||
        	     name[i].equals("rsadsi-MD5withRSAEncryption")) {
            m211.tagtype.write(AsnStatic.ASN_NULL); 
            // parameter is null
          }
        }
        else { // Public key algorithm
          if (name[i].equals("secsig-RSA:") ||
              name[i].equals("secsig-DSA-Common:") ||
              name[i].equals("dsa:")) {
            m211.tagtype.write(AsnStatic.ASN_NONE); 
            // No parameter filled	
          } else if (name[i].equals("secsig-DSA:")) {
            formDSAAlgorithmRule(m211);
          } else if (name[i].equals("rsadsi-rsaEncryption:")) {
            m211.tagtype.write(AsnStatic.ASN_NULL); 
            // parameter is null
          }
        }
      }
    }
  }


}







