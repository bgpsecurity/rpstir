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
import Algorithms.*;
import extensions.*;
import name.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class CrlPane extends CommandPane 
implements ListSelectionListener {

  private String version1, version2;
  private JFrame frame;

  String[] crlData = {
    RuleEditorData.VERSION,
    RuleEditorData.SIGNATURE_ALG,
    RuleEditorData.ISSUER_NAME,
    RuleEditorData.THIS_UPDATE,
    RuleEditorData.NEXT_UPDATE,
    RuleEditorData.REVOKED_CERTS,
    RuleEditorData.CRL_EXTENSIONS
  };

  String[] algoData = {
    "sha256WithRSAEncryption",
    //"sha512WithRSAEncryption",  
    //"sha_1WithRSAEncryption"
  };

  String[] algoID = {
      AlgorithmsStatic.id_sha256WithRSAEncryption,
      //AlgorithmsStatic.id_sha512WithRSAEncryption,
      //    AlgorithmsStatic.id_sha_1WithRSAEncryption
  };

  String[] extnName = {
    RuleEditorData.AUTH_KEY_ID,
    RuleEditorData.CRL_NUMBER,
    //RuleEditorData.ISSUING_DIST_POINTS,
    //    "Authority Information Access",
    //    "Delta CRL Indicator",
    //"Issuing Distribution Point",
  };

  String[] extnOid = {
    ExtensionsStatic.id_authKeyId, //"2.5.29.35",
    ExtensionsStatic.id_cRLNumber, // = "2.5.29.20";
    //ExtensionsStatic.id_issuingDistributionPoint, //"2.5.29.28"
    //ExtensionsStatic.id_cRLDistributionPoints, //"2.5.29.31", 
    // ExtensionsStatic.id_pkix_authorityInfoAccess, //1.3.6.1.5.5.7.1.1
//    ExtensionsStatic.id_deltaCRLIndicator, // = "2.5.29.27";
  };

  String[] extnDefault = {
    RuleEditorData.REQUIRE, //"Authority Key Identifier:",
    RuleEditorData.REQUIRE, //"CRL Number:",
    //RuleEditorData.REQUIRE, // Issuing Distribution Points
    //RuleEditorData.REQUIRE, // Authority Information Access
    //null,//"Delta CRL Indicator:"
  };

  JSplitPane splitPane = new JSplitPane();
  CrlVersionPane crlVersionPane = new CrlVersionPane("CRL");
  AlgoPane algoPane;
  IssuerPane issuerPane;
  ThisUpdatePane thisTimePane = new ThisUpdatePane();
  NextUpdatePane nextTimePane = new NextUpdatePane();
  RevokeCertPane rcPane = new RevokeCertPane("Crl");
  JPanel underPane = new JPanel();
  ExtnPane extnPane = new ExtnPane("CRL", extnName, extnOid, extnDefault);


  public CrlPane() {

    super(RuleEditorData.RuleData[RuleEditorData.CRL_ID]);
    setSplitPane(splitPane);
    type = RuleEditorData.CRL_TYPE;
    ruleName = "CrlRule";
    keyName = "dsa ca";

    if (init())
    System.exit(0);
    initDisplay();

  }

  private void initDisplay() {
    // Create a JList that displays the strings in certData[]
    JList crlList = new JList(crlData);
    crlList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    crlList.setSelectedIndex(0);
    crlList.addListSelectionListener(this);
    JPanel fieldPane = new JPanel();
    //fieldPane.add(crlList);
    JLabel nameListName = new JLabel("CRL Fields" );
    fieldPane.setLayout(new BorderLayout());
    fieldPane.add(nameListName, BorderLayout.NORTH); 
    fieldPane.add(crlList, BorderLayout.CENTER);
    fieldPane.setBorder(BorderFactory.createRaisedBevelBorder());

    splitPane.setLeftComponent(fieldPane);
    splitPane.setRightComponent(crlVersionPane); 
    algoPane = new SigAlgoPane(algoData, algoID, "CRL");
    issuerPane = new IssuerPane();
    //timePane = new TimePane();
    //extnPane = new ExtnPane(extnData);
    // under construction right pane
    JLabel label = new JLabel("This extension is under construction", JLabel.CENTER);
    underPane.add(label);
    updateCAInfo();
    //redraw();
  } 

    public void updateCAInfo()
    {
	extnPane.updateCAInfo();
        issuerPane.updateCAInfo();
	thisTimePane.resetPane();
	nextTimePane.resetPane();
    }

    /*
  public void redraw() {
    issuerPane.redraw();
    extnPane.redraw();
  }
    */
  public void valueChanged(ListSelectionEvent e) {
    if (e.getValueIsAdjusting())
      return;

    JList theList = (JList)e.getSource();
    if (theList.isSelectionEmpty()) {
      splitPane.setRightComponent(null);
    } else {
      int index = theList.getSelectedIndex();
      //displayCertFields(index);
      //System.out.println(" In displayCrlFields(index: " + index + ")");
      switch(index) {
      case 0 /*version*/: splitPane.setRightComponent(crlVersionPane); break;
      case 1 /*signature*/: splitPane.setRightComponent(algoPane); break;
      case 2 /*issuer*/: splitPane.setRightComponent(issuerPane); break;
      case 3 /*this Update*/: splitPane.setRightComponent(thisTimePane); break;
      case 4 /*next Update*/: splitPane.setRightComponent(nextTimePane); break;
      case 5 /* Revoke Cert */: splitPane.setRightComponent(rcPane); break; 
      case 6 /*extensions*/: splitPane.setRightComponent(extnPane); break;
      default:
       JOptionPane.showMessageDialog(frame, "Invalid choice in CRL rule set");    
      }
 
    }
  }

  public int createRule(String ruleName) {
    int good;
    int index = -1;
    int lth;
    AsnByteArray out = new AsnByteArray(500);

    if (RuleUtils.cert.getIssuerName().getItemNum() == 0) {
      JOptionPane.showMessageDialog(frame, 
	  "No active CA.  Please click on \"Retrieve CA's Certificate File \" first", 
	    "", JOptionPane.WARNING_MESSAGE); 
      return RuleEditorData.FAILED;
      
    } 

    RuleChoice rc = new RuleChoice();
    if ((good = RuleUtils.addRuleMember(crlVersionPane, rc, ++index, RuleEditorData.VERSION)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(algoPane, rc, ++index, RuleEditorData.SIGNATURE_ALG)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(issuerPane, rc, ++index, RuleEditorData.ISSUER_NAME)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(thisTimePane, rc, ++index, RuleEditorData.THIS_UPDATE)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(nextTimePane, rc, ++index, RuleEditorData.NEXT_UPDATE)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(rcPane, rc, ++index, RuleEditorData.REVOKED_CERTS)) == RuleEditorData.FAILED) {
      System.out.println("RevokedCertificate  failed");
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((good = RuleUtils.addRuleMember(extnPane, rc, ++index, RuleEditorData.CRL_EXTENSIONS)) == RuleEditorData.FAILED) {
      return good;
    }
    if (good == RuleEditorData.OK) {
      index--;
    }

    if ((lth = rc.encode(out)) < 0) {
      System.out.println(" encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    }

//    rc.put_file(ruleName + ".pre");
//    System.out.println(" **** Done print " + ruleName + ".pre");
        
    // form sign rule request in SKAction format
    RuleUtils.formNsendSKrequest(type, out, lth, keyName, ruleName);

    return good;
  }

  public boolean setRule(RuleChoice rc) 
    {
    int n = rc.sequence.members.numitems();
    //System.out.println("rule has " + n + " members");
    boolean retVal = true;
    for (int i = 0; i < n; i++) 
      {
      Member m = rc.sequence.members.member.index(i);
      int size = m.name.vsize();
      AsnByteArray tmp = new AsnByteArray(size);
      m.name.read(tmp);
      String value = tmp.toString().trim();
  
      if (value.equals(RuleEditorData.VERSION)) 
	retVal = retVal & crlVersionPane.setRule(m);
      else if (value.equals(RuleEditorData.SIGNATURE_ALG)) 
	retVal = retVal & algoPane.setRule(m);
      else if (value.equals(RuleEditorData.ISSUER_NAME)) 
	retVal = retVal & issuerPane.setRule(m);
      else if (value.equals(RuleEditorData.THIS_UPDATE))
	retVal = retVal & thisTimePane.setRule(m);
      else if (value.equals(RuleEditorData.NEXT_UPDATE)) 
	retVal = retVal & nextTimePane.setRule(m);
      else if (value.equals(RuleEditorData.REVOKED_CERTS))
	retVal = retVal & rcPane.setRule(m);
      else if (value.equals(RuleEditorData.CRL_EXTENSIONS))
	retVal = retVal & extnPane.setRule(m);
      }
    return retVal;
    }
}    


