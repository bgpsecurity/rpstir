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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class RuleEditorData {

  // Type of the certificate or CRL 
  public static final String EE_CERT_NAME = "End-Entity Certificate Rule";
  public static final String CROSS_CERT_NAME = "CA Certificate Rule";
  public static final String CRL_NAME = "CRL Rule";
   
  public static final String EE_TYPE = "EE";
  public static final String CA_TYPE = "CA";
  public static final String CRL_TYPE = "CRL";

  public static final String[] RuleData = {
      EE_CERT_NAME, 
      CROSS_CERT_NAME, 
      CRL_NAME, 
    };

  public static final String[] SubjAltNameFields = {
      "Distinguished Name", 
      "RFC822 Address", 
      "IP Address",
      "Domain name"
  };

  public static final String YEARS = "years";
  public static final String MONTHS = "months";
  public static final String WEEKS = "weeks";
  public static final String DAYS = "days";
  public static final String HOURS = "hours";
  public static final String MINUTES = "minutes";

  public static final String COUNTRY_NAME = "Country Name";
  public static final String ORG_NAME = "Organization Name";
  public static final String ORG_UNIT_NAME = "Organizational Unit Name";
  public static final String COMMON_NAME = "Common Name";

  public static final String VERSION = "Version";
  public static final String SERIAL_NUM = "SerialNumber";
  public static final String SIGNATURE_ALG = "Signature Algorithm";
  public static final String ISSUER_NAME = "Issuer Name";
  public static final String VALIDITY_DATES = "Validity Dates";
  public static final String SUBJ_NAME = "Subject Name";
  public static final String SUBJ_PUB_KEY = "Subject Public Key";
  public static final String ISSUER_UID = "Issuer Unique ID";
  public static final String SUBJECT_UID = "Subject Unique ID";
  public static final String EXTENSIONS = "Extensions";
  public static final String CRL_EXTENSIONS = "CRL Extensions";
  public static final String REVOKED_CERTS = "Revoked Certificates";
  public static final String REVOKED_CERT = "Revoked Certificate";
  public static final String NEXT_UPDATE = "Next Update";
  public static final String THIS_UPDATE = "This Update";
  public static final String CRL_NUMBER = "CRL Number";
  public static final String ISSUING_DIST_POINTS = "Issuing Distribution Points";
 
  public static final String SUBJ_KEY_ID = "Subject Key Identifier";
  public static final String KEY_USAGE = "Key Usage";  
  public static final String AUTH_KEY_ID = "Authority Key Identifier";
  public static final String BASIC_CONSTRAINTS = "Basic Constraints";
  public static final String CRL_DIST_POINTS = "CRL Distribution Points";
  public static final String AUTH_INFO_ACCESS = "Authority Information Access";
  public static final String SUBJ_INFO_ACCESS = "Subject Information Access";
  public static final String DISTRIBUTION_POINT = "Distribution Point";
  public static final String DISTRIBUTION_POINT_NAME = "Distribution Point Name";
  public static final String IPADDR_BLOCK = "IP Address Block";
  public static final String AS_ID = "Autonomous System ID";
  public static final String SUBJ_ALT_NAME = "Subject Alternative Name";
  public static final String ISSUER_ALT_NAME = "Issuer Alternative Name";
  public static final String CERT_POLICY = "Certificate Policies";
  public static final String GENERAL_NAMES = "General Names";
  public static final String GENERAL_NAME  = "General Name";

  public static final int ASN_ISSUREUID_TAG = 0x81;
  public static final int ASN_SUBJECTUID_TAG = 0x82;
  public static final int ASN_EXTENSION_TAG = 0xA3;

  public static final int EE_CERT_ID = 0;
  public static final int CROSS_CERT_ID = 1;
  public static final int CRL_ID = 2;

  // Tyep of ThreeWayCombo messages
  public static final int THREE_WAY = 0;
  public static final int TWO_WAY   = 1;
  public static final int YES_NO    = 2;

  public static final Dimension shorterField = new Dimension(40, 20);
  public static final Dimension shortField = new Dimension(80, 20);
  public static final Dimension mediumField = new Dimension(120, 20);
  public static final Dimension longField = new Dimension(180, 20);
  public static final Dimension longerField = new Dimension(260, 20);
  public static final Dimension largeField = new Dimension(300, 30);

  public static final int FAILED = -1; // failed, whole rule back out
  public static final int OK = 0;  // GUI is OK, but no rule formed
  public static final int SUCCESS = 1; //GUI is OK and rule formed

  public static final String PROHIBIT = "Prohibit";
  public static final String ALLOW = "Allow";
  public static final String REQUIRE = "Require";

  public static final int PROHIBIT_NUM = 3;
  public static final int ALLOW_NUM = 2;
  public static final int REQUIRE_NUM = 1;

  public static final String[] ThreeWayData = {
    REQUIRE,
    ALLOW,
    PROHIBIT,
  };

  public static final int digitalSignatureBit = 0x8000;
  public static final int nonRepudiationBit = 0x4000;
  public static final int keyEnciphermentBit = 0x2000;
  public static final int dataEnciphermentBit = 0x1000;
  public static final int keyAgreementBit = 0x0800;
  public static final int keyCertSignBit = 0x0400;
  public static final int cRLSignBit = 0x0200;
  public static final int encipherOnlyBit = 0x0100;
  public static final int decipherOnlyBit = 0x0080;

  public static final int IPV4 = 1;
  public static final int IPV6 = 2;

}
