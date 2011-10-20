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
import Algorithms.*;
import skaction.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

abstract class CertPane extends CommandPane 
implements ListSelectionListener {
  private String version1, version2, version3;
  private String sNumChoice;

  public String printTitle = null;
  public String[] certData = null;
  public String[] algoData = null;
  public String[] algoID = null;
  public String[] keyAlgoData = null;
  public String[] keyAlgoID = null;
  public String[] DNData = null;
  public String[] DNID = null;
  public String[] extnData = null;
  public String[] extnOID = null;
  public String[] defaultValue = null;
  private JFrame frame=null;
  private JList certList = null;
 
  JSplitPane splitPane = new JSplitPane();
  CertVersionPane certVersionPane;
  SerialNumPane numberPane = new SerialNumPane();
  AlgoPane algoPane;
  IssuerPane issuerPane;
  TimePane timePane; // hour, minutes and seconds should be 00
  SubjectPane subjectPane;    
  SubjectKeyPane subjectKeyPane; // 1024 bits
  IssuerUIDPane issuerUIDPane; //not used 
  SubjectUIDPane subjectUIDPane;  //not used 
  ExtnPane extnPane; 

  public CertPane(int id) {
    super(RuleEditorData.RuleData[id]);
    setSplitPane(splitPane);
    setData();

    certVersionPane = new CertVersionPane(type);
    if (init())
    System.exit(0);
    initDisplay();

  }

  public abstract void setData();

  public int getFieldIndex(String name) {
      String[] allCertData = {
	RuleEditorData.VERSION,
	RuleEditorData.SERIAL_NUM,
	RuleEditorData.SIGNATURE_ALG,
	RuleEditorData.ISSUER_NAME,
	RuleEditorData.VALIDITY_DATES,
	RuleEditorData.SUBJ_NAME,
	RuleEditorData.SUBJ_PUB_KEY,
	RuleEditorData.ISSUER_UID,
	RuleEditorData.SUBJECT_UID,
	RuleEditorData.EXTENSIONS
      };
    
    for (int i = 0; i < allCertData.length; i++) {
      if (name.compareTo(allCertData[i]) == 0) {
	return i;
      }
    }

    return -1;

  }
	

  private void initDisplay() {
    // Create a JList that displays the strings in certData[]
    certList = new JList(certData);
    certList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    certList.setSelectedIndex(0);
    //certList.setSelectedIndex(3);
    certList.addListSelectionListener(this);
    JPanel fieldPane = new JPanel();
    JLabel nameListName = new JLabel("Certificate Fields" );
    fieldPane.setLayout(new BorderLayout());
    fieldPane.add(nameListName, BorderLayout.NORTH); 
    fieldPane.add(certList, BorderLayout.CENTER);
    fieldPane.setBorder(BorderFactory.createRaisedBevelBorder());

    algoPane = new SigAlgoPane(algoData, algoID, type);
    issuerPane = new IssuerPane();
    timePane = new TimePane();
    subjectPane = new SubjectPane(DNData, DNID, type);
    subjectKeyPane = new SubjectKeyPane(keyAlgoData, keyAlgoID, type);
    issuerUIDPane = new IssuerUIDPane();
    subjectUIDPane = new SubjectUIDPane();
    extnPane = new ExtnPane(type, extnData, extnOID, defaultValue);

    splitPane.setLeftComponent(fieldPane);
    setRightComponent(certList);
    updateCAInfo();
  } 

  public void checkCertExtensions()
  {
    boolean goodExt = extnPane.checkExtensions();
    //System.out.println("Checking extensions returned " + goodExt);
    while (!goodExt)
    {
        int n =	JOptionPane.showConfirmDialog(frame, 
              "Error in Certificate Extensions.  Unable to proceed.\n" +
	      "Would you like to pick another file?", 
              "Certificate Error", JOptionPane.ERROR_MESSAGE);
	if (n == JOptionPane.NO_OPTION)
	    System.exit(1);
	//System.out.println("checkCertExtensions");
	goodExt = RuleUtils.cert.newCA(true, true);
	extnPane.updateCAInfo();
	//System.out.println("After newCA in certpane " +  goodExt);
	if (goodExt)
	    goodExt = extnPane.checkExtensions();
	//System.out.println("After checkextensions " +  goodExt);
    }
  }

  public void updateCAInfo()
  {
      extnPane.updateCAInfo();
      checkCertExtensions();
      issuerPane.updateCAInfo();
      subjectPane.resetPane();
      timePane.resetPane();
  }
    /*
  public void redraw() {
      System.out.println("calling certpane redraw.  outdate routine.");
    issuerPane.redraw();
    subjectPane.redraw();
    extnPane.redraw();
  }
    */
  public void valueChanged(ListSelectionEvent e) {
    if (e.getValueIsAdjusting())
      return;

    JList theList = (JList)e.getSource();
    setRightComponent(theList);
  }

  private void setRightComponent(JList theList)
  {
      if (theList == null)
	  theList = certList;
      if (theList.isSelectionEmpty()) 
	  splitPane.setRightComponent(null);
      else 
      {
	  String name = theList.getSelectedValue().toString();
	  int index = getFieldIndex(name);
	  switch(index) 
	  {
	  case 0 /*version*/: 
	      splitPane.setRightComponent(certVersionPane); 
	      break;
	  case 1 /*serialNum*/: 
	      splitPane.setRightComponent(numberPane); 
	      break;
	  case 2 /*signature*/: 
	      splitPane.setRightComponent(algoPane); 
	      break;
	  case 3 /*issuer*/: 
	      //issuerPane.redraw(); 
	      splitPane.setRightComponent(issuerPane); 
	      break;
	  case 4 /*validityDates*/: 
	      splitPane.setRightComponent(timePane); 
	      break;
	  case 5 /*subject*/: 
	      //subjectPane.redraw(); 
	      splitPane.setRightComponent(subjectPane); 
	      break;
	  case 6 /*subjectPublickeyInfo*/: 
	      splitPane.setRightComponent(subjectKeyPane); 
	      break;
	  case 7 /*IssuerUniqueID*/: 
	      splitPane.setRightComponent(issuerUIDPane); 
	       break;
	  case 8 /*subjectUniqueID*/: 
	      splitPane.setRightComponent(subjectUIDPane); 
	      break;
	  case 9 /*extensions*/: 
	      splitPane.setRightComponent(extnPane); 
	      break;
          default:
              System.out.println("Invalid field name in setRightComponent");
	  }
      }
  }

  private void vVRule(RuleChoice rc, int ind, String msg, int id, boolean extn) {

    rc.sequence.groupRules.groupRule.index(ind).insert();
    GroupRule g = (GroupRule)rc.sequence.groupRules.groupRule.index(ind);
    g.name.write(msg);

    g.ifcase.locations.location.index(0).insert();
    g.ifcase.locations.location.index(0).path.write("d");
    g.ifcase.locations.location.index(1).insert();
    g.ifcase.locations.location.index(1).tagtype.write(id);;

    /*g.ifcase.rule.add();
    Rule p = g.ifcase.rule.ref.primitive;
    p.targets.allow.target.index(0).insert();
    p.targets.allow.target.index(0).tagtype.write(id);*/

    g.thencase.locations.location.index(0).insert();
    g.thencase.locations.location.index(0).path.write("dd");
    g.thencase.rule.add();
    Rule p = g.thencase.rule.ref.primitive;

    if (!extn) {
      p.targets.allow.target.index(0).insert();
      p.targets.allow.target.index(0).num.write(1);
      p.targets.allow.target.index(1).insert();
      p.targets.allow.target.index(1).num.write(2);
    }
    else { // Extn
      p.targets.require.target.index(0).insert();
      p.targets.require.target.index(0).num.write(2);
    }

  }

  private void createIUIDvVRule(RuleChoice rc, int ind) {
    vVRule(rc, ind, "IssuerUnique ID vs. Version", RuleEditorData.ASN_ISSUREUID_TAG,false); //0x81

  }

  private void createSUIDvVRule(RuleChoice rc, int ind) {
    vVRule(rc, ind, "SubjectUniqueID vs. Version", RuleEditorData.ASN_SUBJECTUID_TAG, false);  //0x82

  }

  private void  createExtvVRule(RuleChoice rc, int ind) {
    vVRule(rc, ind, "Extensions vs. Version", RuleEditorData.ASN_EXTENSION_TAG, true);  //0xA3

  }

  public int createRule(String ruleName) {
    int good;       // 1 correct; 0 : correct but no rule; -1: error
    int index = -1;
    int lth;
    AsnByteArray out; // = new AsnByteArray(500);
        
    if (RuleUtils.cert == null) {
      JOptionPane.showMessageDialog(frame, 
				    "No active CA.  Please click on \"Retrieve CA's Certificate File \" first", 
				    "", JOptionPane.WARNING_MESSAGE); 
      return RuleEditorData.FAILED;
    } 

    RuleChoice rc = new RuleChoice();
    if ((good = RuleUtils.addRuleMember(certVersionPane, rc, ++index, RuleEditorData.VERSION)) == RuleEditorData.FAILED) {
      //JOptionPane.showMessageDialog(frame,
      //			    "No version set to Allow or Require.\nPlease click on Version field to select the version"); 
      System.out.println(" Version failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(numberPane, rc, ++index, RuleEditorData.SERIAL_NUM)) == RuleEditorData.FAILED) {
      System.out.println(" serial number failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(algoPane, rc, ++index, RuleEditorData.SIGNATURE_ALG)) == RuleEditorData.FAILED) {
      System.out.println(" algorithm failed at " + rc.error.asn_map_string);
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(issuerPane, rc, ++index, RuleEditorData.ISSUER_NAME)) == RuleEditorData.FAILED) {
      System.out.println(" issuer failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(timePane, rc, ++index, RuleEditorData.VALIDITY_DATES)) == RuleEditorData.FAILED) {
      System.out.println(" time failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(subjectPane, rc, ++index, RuleEditorData.SUBJ_NAME)) 
        == RuleEditorData.FAILED) {
      System.out.println(" subject name failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(subjectKeyPane, rc, ++index, RuleEditorData.SUBJ_PUB_KEY)) == RuleEditorData.FAILED) {
      System.out.println(" subject key failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(issuerUIDPane, rc, ++index, RuleEditorData.ISSUER_UID)) == RuleEditorData.FAILED) {
      System.out.println(" issuerUID failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }
    

    if ((good = RuleUtils.addRuleMember(subjectUIDPane, rc, ++index, RuleEditorData.SUBJECT_UID)) == RuleEditorData.FAILED) {
      System.out.println(" subjectUID failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(extnPane, rc, ++index, RuleEditorData.EXTENSIONS)) == RuleEditorData.FAILED) {
      System.out.println(" extension failed");
      return good;
    }

    // add Cert's group rule.  it will be just hard coded.
    index = -1;
    createIUIDvVRule(rc, ++index);
    createSUIDvVRule(rc, ++index);
    createExtvVRule(rc, ++index);

    lth = rc.vsize();
    out = new AsnByteArray(lth + 100);
    if ((lth = rc.encode(out)) < 0) {
      System.out.println("certPane encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    }
    
//    rc.put_file(ruleName + ".pre");
//    System.out.println(" **** Done print " + ruleName + ".pre");
    
    // from sign rule request in SKAction format
    RuleUtils.formNsendSKrequest(type, out, lth, keyName, ruleName);
    
    out = null;
    return good;
  }

  public boolean setRule(RuleChoice rc) {
    int n = rc.sequence.members.numitems();
    //System.out.println("In CertPane.setRule -- rule has " + n + " members");
    boolean retVal = true;

    for (int i = 0; i < n; i++) {
      Member m = rc.sequence.members.member.index(i);
      int size = m.name.vsize();
      AsnByteArray tmp = new AsnByteArray(size);
      m.name.read(tmp);
      String value = tmp.toString();

      if ((value.trim()).equals(RuleEditorData.VERSION)) { // done
	retVal = retVal & certVersionPane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.SERIAL_NUM)) { // done
	retVal = retVal & numberPane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.SIGNATURE_ALG)) { //done
	retVal = retVal & algoPane.setRule(m);  
      }
      else if ((value.trim()).equals(RuleEditorData.ISSUER_NAME)) { //done
	retVal = retVal & issuerPane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.VALIDITY_DATES)) { //done
	retVal = retVal & timePane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.SUBJ_NAME)) { // done, need testing
	retVal = retVal & subjectPane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.SUBJ_PUB_KEY)) { //done, need testing
	retVal = retVal & subjectKeyPane.setRule(m);
      }
      /*
      else if ((value.trim()).equals(RuleEditorData.ISSUER_UID)) {
	retVal = retVal & issuerUIDPane.setRule(m);
      }
      else if ((value.trim()).equals(RuleEditorData.SUBJECT_UID)) {
	retVal = retVal & subjectUIDPane.setRule(m);
      }
      */
      else if ((value.trim()).equals(RuleEditorData.EXTENSIONS)) {
	retVal = retVal & extnPane.setRule(m);
      }
    }
    return retVal;
  }
  
}
