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
import Algorithms.*;
import extensions.*;
import name.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class EECertPane extends CertPane 
implements ListSelectionListener {

  EECertPane() {
      super(RuleEditorData.EE_CERT_ID);
  }
 
  public void setData() {
      String myPrintTitle = "*** Create Registry & ISP Cert Rule";
      String myRuleName = "CertRule";
      String myKeyName = "rsa ee";

  String[] myCertData = 
    {
    RuleEditorData.VERSION,
    RuleEditorData.SIGNATURE_ALG,
    RuleEditorData.ISSUER_NAME,
    RuleEditorData.VALIDITY_DATES,
    RuleEditorData.SUBJ_NAME,
    RuleEditorData.SUBJ_PUB_KEY,
    RuleEditorData.EXTENSIONS
    };

   String[] myAlgoData = {
      "sha256WithRSAEncryption",
      //"sha512WithRSAEncryption",
      //"rsadsi-sha-1WithRSAEncryption" // RFC 3779 designated one
  };

  String[] myAlgoID = {
    AlgorithmsStatic.id_sha256WithRSAEncryption,
    //AlgorithmsStatic.id_sha512WithRSAEncryption,
    //AlgorithmsStatic.id_sha_1WithRSAEncryption //"1.2.840.113549.1.1.5
  };

  String[] myKeyAlgoData = { 
      "rsadsi-rsaEncryption",
  };

  String[] myKeyAlgoID = { 
      AlgorithmsStatic.id_rsadsi_rsaEncryption, //"1.2.840.113549.1.1.1",
  };

  String[] myDNData = {
    RuleEditorData.COUNTRY_NAME,
    RuleEditorData.ORG_NAME,
    RuleEditorData.ORG_UNIT_NAME,
    RuleEditorData.COMMON_NAME,
  };

   String[] myDNID = {
       //NameStatic.id_at_dc, //"0.9.2342.19200300.100.1.25", 
     NameStatic.id_countryName, // 2.5.4.6
     NameStatic.id_organizationName, // 2.5.4.10
     NameStatic.id_organizationalUnitName, // 2.5.4.11
     NameStatic.id_commonName, //"2.5.4.3", // commonname
     //NameStatic.id_emailAddress, // 1.2.840.113549.1.9.1
   };
   
   String[] myExtnData = {
      RuleEditorData.IPADDR_BLOCK,
      RuleEditorData.AS_ID,
      RuleEditorData.SUBJ_KEY_ID,
      RuleEditorData.AUTH_KEY_ID,
      RuleEditorData.KEY_USAGE,
      RuleEditorData.CERT_POLICY,
      RuleEditorData.CRL_DIST_POINTS,
      RuleEditorData.AUTH_INFO_ACCESS,
      RuleEditorData.SUBJ_INFO_ACCESS,
      RuleEditorData.SUBJ_ALT_NAME,
   };
   
   String[] myExtnOID = {
     ExtensionsStatic.id_pe_ipAddrBlocks, //"1.3.6.1.5.5.7.1.7",//IP Address Block:
     ExtensionsStatic.id_pe_autonomousSysIds, //"1.3.6.1.5.5.7.1.8",//Autonomous System Identifier
     ExtensionsStatic.id_subjectKeyIdentifier, //"2.5.29.14", //"Subject Key Identifier:",
     ExtensionsStatic.id_authKeyId, //"2.5.29.35", //"Auth Key ID:",
     ExtensionsStatic.id_keyUsage, //"2.5.29.15", //"Key Usage:",
     ExtensionsStatic.id_certificatePolicies, //"2.5.29.32", //"Certificate Policies:",
     ExtensionsStatic.id_cRLDistributionPoints, //"2.5.29.31", //"CRL Distribution Points:",
     ExtensionsStatic.id_pe_authorityInfoAccess, //1.3.6.1.5.5.7.1.1
     ExtensionsStatic.id_pe_subjectInfoAccess, //1.3.6.1.5.5.7.1.11
     ExtensionsStatic.id_subjectAltName, //"2.5.29.17", //"Subject Alt Name:",
   };
   
   String[] myDefault = {
     null,//IP Address Block:
     null,//Autonomous System Identifier
     "Require",//"Subject Key Identifier:",
     "Require",//	"Auth Key ID:",
     "Require",//	"Key Usage:",
//     null, //""Name Constraints:",
     "Require",//	"Certificate Policies:",
     "Require",// CRL Distribution Points
     "Require",// Authority Info Access
     "Prohibit",// Subject Info Access
     null,//	"Subject Alt Name:",
   };
   
   
   extnData = new String[myExtnData.length];
   extnData = myExtnData;
   extnOID = myExtnOID;
   defaultValue = myDefault;
   printTitle = myPrintTitle;
   ruleName = myRuleName;
   keyName = myKeyName;
   type = RuleEditorData.EE_TYPE;
   
   certData = myCertData;
   algoData = myAlgoData;
   algoID = myAlgoID;
   keyAlgoData = myKeyAlgoData;
   keyAlgoID = myKeyAlgoID;
   DNData = myDNData;
   DNID = myDNID;
  }
    
}







