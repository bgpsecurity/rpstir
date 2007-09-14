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
import extensions.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class ExtnPane extends ExtnBasePane 
  implements NameListener, ActionListener {
  private String myType;
  private String[] myExtnData;
  private String[] myExtnOID;
  private String[] myDefault;
  //private String[] myKUdata;
  private JSplitPane splitPane = new JSplitPane();
  NamePane leftPane;
  JPanel rightPane = new JPanel();
  JPanel underPane = new JPanel();
  JPanel prohibitPane = new JPanel();
  SKIPane skiPane;
  //SKIPane skiPane = new SKIPane("Subject Key Identifier");
  //KUEEPane kueePane = new KUEEPane();
  //KUCAPane kucaPane = new KUCAPane();
  KUPane kuPane;
  AlternativeNamePane sanPane;
  AlternativeNamePane ianPane;
  BasicConstraintPane bcPane = new BasicConstraintPane();
  CertPolicyPane cpPane;
  AKIPane akiPane;
  JPanel AIApane;
  IPAddrPane ipaPane;
  AutoSystemPane asPane;
    //RouterIdPane riPane;
  CrlNumPane crlNumPane = new CrlNumPane();
      //DeltaCrlIndPane deltaCIPane = new DeltaCrlIndPane();
  IssueDistPointPane issueDistPointPane;
  SubjectInfoPane subjInfoPane;
  CrlDistPointPane crlDistPointPane;
  AuthInfoPane authInfoPane;
    //CrlDistPointPane crlDistPointPane;
    //AuthKeyIdExtn authKeyIDPane;
  String[] dnName;
  JDialog dialog;

  String[] DNData = {
      RuleEditorData.COUNTRY_NAME,
      RuleEditorData.ORG_NAME,
      RuleEditorData.ORG_UNIT_NAME,
      RuleEditorData.COMMON_NAME, 
  };

  static String[] v4List = {
    "SAFI 0\t 10.0.0.0 - 10.255.255.255",
    "SAFI 1\t 006/8",
    "SAFI 1\t 015/8 - 022/8",
    "SAFI 1\t 128/1-172.0/12",
    "SAFI 3\t 204/8-209/8" 
  };

  static String[] v6List = {
    "SAFI 2\t 2001:0:2/48",
    "SAFI 4\t 2345",
    "SAFI 5\t 2001:0:2::1",
    "SAFI 6\t 500 - 1000" 
  };

  static String[] asnList = {
    "100 - 2000",
    "2345",
    "500 - 1000" 
  };

  static String[] rdiList = {
    "100 - 2000",
    "2345",
    "500 - 1000" 
  };

  public ExtnPane(String type,
		  String[] extnData, 
		  String[] extnOID) {
    this(type, extnData, extnOID, null); 
  }

  public ExtnPane(String type, 
		  String[] extnData, 
		  String[] extnOID, 
		  String[] defaultValue) {
    super(type);
    myType = type;
    myExtnData = extnData;
    myExtnOID = extnOID;
    myDefault = defaultValue;
    //myKUdata = kuData;
    setSplitPane(splitPane);
    ipaPane = new IPAddrPane("IP Address Block", v4List, v6List);
    asPane = new AutoSystemPane("Autonomous System Identifiers", asnList, rdiList);
    //riPane = new RouterIdPane("Router Identifier");
    akiPane = new AKIPane("Authority Key Identifier", myType);
    skiPane = new SKIPane(myType);
    kuPane = new KUPane(myType);
    authInfoPane = new AuthInfoPane(myType);
    crlDistPointPane = new CrlDistPointPane(myType);
    subjInfoPane = new SubjectInfoPane(myType);
    issueDistPointPane = new IssueDistPointPane(myType);
    dnName = DNData;
    //} else {
    //  dnName = null;
    //}
    sanPane = new AlternativeNamePane(RuleEditorData.SUBJ_ALT_NAME, RuleEditorData.PROHIBIT, myType);
    ianPane = new AlternativeNamePane(RuleEditorData.ISSUER_ALT_NAME, RuleEditorData.PROHIBIT, myType);
    cpPane = new CertPolicyPane(myType);
    if (init())
      System.exit(0);
    initDisplay();
    //System.out.println("about to set to ip");
    //splitPane.setRightComponent(rightPane);
    
  }

  public String getChoice(int i) {
      return(leftPane.getChoice(i));
  }

  static void mustBeCritical(Members m21, int index) {
    m21.member.index(index).insert();
    Member m211 = (Member)m21.member.index(index);
    m211.rule.add();
    Rule p = m211.rule.ref.primitive;
    p.targets.require.target.index(0).insert();
    //p.targets.require.target.index(0).value.write(0xFF);
    p.targets.require.target.index(0).num.write(-1);
  }
  
  static void mustNotCritical(Members m21, int index) {
    m21.member.index(index).insert();
    Member m211 = (Member)m21.member.index(index);
    m211.tagtype.write(AsnStatic.ASN_NONE);
  }
  
  static void maybeCritical(Members m21, int index) {
    m21.member.index(index).insert();
    Member m211 = (Member)m21.member.index(index);
    m211.optional.write(AsnStatic.ASN_BOOL_TRUE);
    m211.rule.add();
    Rule p = m211.rule.ref.primitive;
    p.targets.allow.target.index(0).insert();
    //p.targets.allow.target.index(0).value.write(0xFF);
    p.targets.allow.target.index(0).num.write(-1);
  }

  static void setCriticality(Members m21, int index, String critical) {
    if (critical == RuleEditorData.ALLOW) {  
      maybeCritical(m21, index);
    }
    else if (critical.equals(RuleEditorData.REQUIRE)) {
      mustBeCritical(m21, index);
    }
    else if (critical.equals(RuleEditorData.PROHIBIT)) {
      mustNotCritical(m21, index);
    }
  }
  
  public int createRule(Member m) {
    int i;
    int lth;
    AsnByteArray out = new AsnByteArray(500);
    Rule p;
    boolean hasRequire = false;
    boolean hasAllowRequire = false;
    String critical = RuleEditorData.ALLOW;

    for (i = 0; i < myExtnOID.length; i++) {      
      if (getChoice(i).equals(RuleEditorData.ALLOW) || 
	  getChoice(i).equals(RuleEditorData.REQUIRE)) {
	hasAllowRequire = true;
      }
    }
    if (!hasAllowRequire) { // no extensions requested
      return RuleEditorData.SUCCESS;
    }
    
    if (myType.indexOf("CRL") != -1) { // CRL
      m.name.write("CRL Extensions");
      m.tagtype.write(AsnStatic.ASN_CONT_CONSTR); // A0
    } else {
      m.name.write("Extensions");
      m.tagtype.write(AsnStatic.ASN_CONT_CONSTR | 3); // A3
    }
    m.rule.add();
    m.rule.ref.sequence.members.member.index(0).insert();
    Member mm = m.rule.ref.sequence.members.member.index(0);
    mm.name.write("Extension Array");
    mm.tagtype.write(AsnStatic.ASN_SEQUENCE);
    mm.rule.add();
    SetSeqOfRule sso = mm.rule.ref.seqOf;
    sso.member.name.write("Extension");
    sso.member.tagtype.write(AsnStatic.ASN_SEQUENCE);
    sso.member.rule.add();
    RuleChoice rc = sso.member.rule.ref;

    // permitted OIDs
    rc.definerSeq.members.member.index(0).insert();
    Member m1 = rc.definerSeq.members.member.index(0);
    m1.name.write("Permitted OIDs");
    m1.tagtype.write(AsnStatic.ASN_OBJ_ID); //0x06

    m1.rule.add();
    p = m1.rule.ref.definerRule;// Rule 

    // get extension's OID and availability
    // if at least one is required, we need to have group rule for it.
    int index = -1;
    for (i = 0; i < myExtnOID.length; i++) {      
      if (getChoice(i).equals(RuleEditorData.ALLOW) || 
	  getChoice(i).equals(RuleEditorData.REQUIRE)) {
	p.targets.allow.target.index(++index).insert();
	((Target)p.targets.allow.target.index(index)).objid.write(myExtnOID[i]);
      }
    }
    if ((lth = m.encode(out)) < 0) { // In real production this should not happen
      System.out.println("extension permitted OID encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } else {
   //   System.out.println("extension permitted OID succeeded"); 
    }
    out = null;

    // critical flags
    //Add definedBy member
    rc.definerSeq.members.member.index(1).insert();
    Member m2 = (Member)rc.definerSeq.members.member.index(1);
    m2.name.write("Critical flag");
    m2.tagtype.write(AsnStatic.ASN_BOOLEAN); //0x01
//    m2.optional.write(AsnStatic.ASN_BOOL_TRUE);
    m2.rule.add();
    Members m21 = (Members)m2.rule.ref.definedBy;// CompoundRule 26
    for (i = 0, index = -1; i < myExtnOID.length; i++) {
      String extnName = getExtnName(i);
      // Add definedBy parameters
      if (getChoice(i).equals(RuleEditorData.ALLOW) || 
	  getChoice(i).equals(RuleEditorData.REQUIRE)) {
	if (getChoice(i).equals(RuleEditorData.REQUIRE)) {
	  hasRequire = true;
	}
	ExtnFieldBasePane o = getExtnPane(i);
	if (o != null) {
	  critical = o.getCriticality();
	  setCriticality(m21, ++index, critical);
	} else {
	  maybeCritical(m21, ++index); 
	}
      }
    }
    if ((lth = m.size()) < 0) { // In real production this should not happen
      System.out.println("extension criticality encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } else {
   //   System.out.println("extension criticality succeeded"); 
    }
    out = null;

    // extnValue: Octet string wrapper
    rc.definerSeq.members.member.index(2).insert();
    Member m3 = rc.definerSeq.members.member.index(2);
    m3.name.write("Octet string wrapper");
    m3.tagtype.write(AsnStatic.ASN_OCTETSTRING); //0x01
    // m3.optional.write(AsnStatic.ASN_BOOL_TRUE);
    m3.rule.add();
    
    m3.rule.ref.wrapper.rule.add();// wrapper 
    Members m31 = m3.rule.ref.wrapper.rule.ref.definedBy;
    // get extnValue
    for (i = 0, index = -1; i < myExtnOID.length; i++) 
      {
      // Add definedBy parameters
      if (getChoice(i).equals(RuleEditorData.ALLOW) || 
	  getChoice(i).equals(RuleEditorData.REQUIRE)) 
        {
	m31.member.index(++index).insert();
	Member m311 = (Member)m31.member.index(index);
	ExtnFieldBasePane o = getExtnPane(i);
	if (o != null && o.createRule(m311) == RuleEditorData.FAILED) 
          {
	  m31.member.index(index).remove();	    
	  index--;
	  System.out.println(" extension " + i + " failed.");
	  return RuleEditorData.FAILED;  
	  }
        }
      }
    if ((lth = m.size()) < 0) 
      { // In real production this should not happen
      System.out.println("extension wrapper encode out = " + lth + " " + AsnErrorMap.asn_map_string);
      } 
    //else System.out.println("extension wrapper succeeded"); 
    
    out = null;

    // GroupRule for required extns
    if (hasRequire)
      {
      sso.groupRules.groupRule.index(0).insert();
      GroupRule gr = sso.groupRules.groupRule.index(0);
      gr.name.write("Required extension");
      gr.thencase.rule.add();
      SpecialRule s = gr.thencase.rule.ref.special;
      s.type.write(0x07);  //id-limits
      s.value.limits.location.path.write("dad");
      index = -1;
      for (i = 0; i < myExtnOID.length; i++) 
        {
	// Add groupRule
	if (getChoice(i).equals(RuleEditorData.REQUIRE)) 
          {
	  s.value.limits.valAndLimit.idAndLimit.index(++index).insert();
	  IdAndLimit il = (IdAndLimit)s.value.limits.valAndLimit.idAndLimit.index(index);
	  il.id.objid.write(myExtnOID[i]);
	  il.max.write(1); 
	  il.min.write(1);
	  }
        }
      }
    if ((lth = m.size()) < 0) { // In real production this should not happen
      System.out.println("extension group rule 1 encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } else {
    //  System.out.println("extension group rule 1 succeeded"); 
    }
    out = null;
    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) 
    {
    AsnIntRef tagRef = new AsnIntRef();
    AsnByteArray tmpOid = new AsnByteArray(200); //oid
    String tmp;
    int i, ni, ind;
    int n = myExtnOID.length;
    String[] res = new String[n]; // indexing to ThreeWayData
    boolean retVal = true;

    // reset subject information access, crl distribution points, authority information access
    resetContents();
    for (i = 0; i < n; i++) {
	res[i] = RuleEditorData.PROHIBIT; // default is prohibit
    }
 
    // get allowed extn ID
    if (m.rule == null || m.rule.ref == null || m.rule.ref.sequence == null ||
      m.rule.ref.sequence.members == null || m.rule.ref.sequence.members.numitems() == 0)
      return true;
    Member mm = m.rule.ref.sequence.members.member.index(0);
    if (mm.rule == null || mm.rule.ref == null || mm.rule.ref.seqOf == null)
      return true;
    SetSeqOfRule sso = mm.rule.ref.seqOf;
    RuleChoice rc = sso.member.rule.ref;
    if (rc.definerSeq == null || rc.definerSeq.members == null ||
      rc.definerSeq.members.numitems() == 0) return true;
    Member m1 = rc.definerSeq.members.member.index(0);
    if (m1 != null && m1.rule.ref != null && m1.rule.ref.definerRule != null)
      {
      Rule p = m1.rule.ref.definerRule;// Rule
      if (p.targets != null && p.targets.allow != null)
        { 
        Targets targs = p.targets.allow;  // set the allows
        //System.out.println("allows " + p.targets.allow.numitems() +
        // " requires " + p.targets.require.numitems());
        if ((ni = targs.numitems()) > 0)
          {
          //System.out.println(" extn allow num: " + ni);
          for (i = 0; i < ni; i++) 
            {
            //System.out.println("i = " + i);
            Target ta = targs.target.index(i);
            tmpOid = new AsnByteArray(ta.objid.vsize());
            ta.objid.read(tmpOid);
            //tmpOid.print();
            tmp = tmpOid.toString();  
            //System.out.println(" algo (allow): " + tmp.trim());
            ind = RuleUtils.getOidIndex(myExtnOID, tmp);
            //System.out.println("ind " + ind);
            res[ind] = RuleEditorData.ALLOW;
            //System.out.println("Allow " + tmp + " " + res[ind]);
            }
          }
        }
      }
    for (i = 0; i < n; i++) 
      {
      leftPane.setChoice(i, res[i]); 
      //System.out.println(i + " " + res[i]);
      }

    // get critical flag
    Member m2 = rc.definerSeq.members.member.index(1);
    if (m2 != null && m2.rule != null && m2.rule.ref != null &&
      m2.rule.ref.definedBy != null)
      {
      Members m21 = (Members)m2.rule.ref.definedBy;// CompoundRule 26
      ni = m21.numitems();
      for (i = 0; i < ni; i++) 
        {
        ExtnFieldBasePane o = getExtnPane(i);
        if (o != null) 
          { 
	  Member m211 = (Member)m21.member.index(i);
          if (m211.rule.ref == null) 
            { // prohibit, mustnotcritical
            o.setCriticality(RuleEditorData.PROHIBIT);
	    } 
          else 
            { // Allow and Require
	    Rule p = m211.rule.ref.primitive;
	    p.targets.tag(tagRef); 
            switch(tagRef.val)  
              {
	    case 0xA1: // Allow, may be critical
	      o.setCriticality(RuleEditorData.ALLOW);
	      break;
	    case 0xA2: // require, must be critical
	      o.setCriticality(RuleEditorData.REQUIRE);
	      break;
	      }
	    }
          }
        }
      }
    // get rule
    Member m3 = rc.definerSeq.members.member.index(2);
    if (m3 != null && m3.rule != null && m3.rule.ref != null &&
      m3.rule.ref.wrapper != null && m3.rule.ref.wrapper.rule != null &&
      m3.rule.ref.wrapper.rule.ref != null && 
      m3.rule.ref.wrapper.rule.ref.definedBy != null)
      {    
      Members m31 = m3.rule.ref.wrapper.rule.ref.definedBy;
      ni = m31.numitems();
      for (i = 0; i < ni; i++) 
        { 
        String name;
        AsnByteArray aba = new AsnByteArray();
        m31.member.index(i).name.read(aba);
        if (aba == null || aba.getLength() == 0) continue;
        //System.out.println(" extn name(" + i + "): " + aba.toString());
        ExtnFieldBasePane o = getExtnPane(aba.toString().trim());
        if (o != null) 
          { 
          Member m311 = (Member)m31.member.index(i);
          aba = new AsnByteArray();
          m311.name.read(aba);
          //System.out.println("Member " + aba.toString());
          //System.out.println("Calling setRule for " + aba.toString());
          retVal &= o.setRule(m311);
          }
        }
      }
    // get required extn
    GroupRule gr = sso.groupRules.groupRule.index(0);
    if (gr.thencase.rule.ref != null && gr.thencase.rule.ref.special != null) 
      {
      SpecialRule s = gr.thencase.rule.ref.special;
      if (s.value != null && s.value.limits != null && 
        s.value.limits.valAndLimit != null)
        {
        IdAndLimits idAndLimits = s.value.limits.valAndLimit;
        ni = idAndLimits.numitems();
        for (i = 0; i < ni; i++) 
          {
	  AsnObjectIdentifier nobjid = idAndLimits.idAndLimit.index(i).id.objid;
          if (nobjid != null)
            {
            tmpOid = new AsnByteArray(nobjid.size());
            nobjid.read(tmpOid);
	    tmp = tmpOid.toString();  
            //System.out.println(" extn (required): \"" + tmp.trim() + "\"");		
            ind = RuleUtils.getOidIndex(myExtnOID, tmp);
	    res[ind] = RuleEditorData.REQUIRE;
            }
          }
        }  
      }
      // set extn choices
    for (i = 0; i < myExtnOID.length; i++) 
      {
      System.out.println("Extn " + i + " choice " + res[i]);
      leftPane.setChoice(i, res[i]);
      }
    if ((leftPane.getChoice(0) == RuleEditorData.PROHIBIT) && 
        (leftPane.getChoice(1) == RuleEditorData.PROHIBIT))
	retVal = false;
    else if (leftPane.getChoice(0) == RuleEditorData.PROHIBIT)
    {
	 leftPane.setChoice(1,RuleEditorData.REQUIRE);
	 leftPane.setEnabled(1, false);
    }
    else if (leftPane.getChoice(1) == RuleEditorData.PROHIBIT)
    {
	 leftPane.setChoice(0,RuleEditorData.REQUIRE);
	 leftPane.setEnabled(0, false);
    }
    else
    {
	leftPane.setEnabled(0, true);
	leftPane.setEnabled(1, true);
    }
    //System.out.println("ExtnPane setRule, before checkIPASNumBlock sizes");
    //checkExtensions();
    return retVal;
    }

  private ExtnFieldBasePane getExtnPane(int i) {
    String extnName = getExtnName(i);

    return getExtnPane(extnName);
  }
  
  private ExtnFieldBasePane getExtnPane(String extnName) {
    ExtnFieldBasePane o = null;
    //System.out.println(extnName + "---");
    if (extnName.indexOf(RuleEditorData.SUBJ_KEY_ID) >=0 ) { //done
	o = skiPane; 
    } else if (extnName.indexOf(RuleEditorData.KEY_USAGE) >=0 ) { //done
      o = kuPane;
    } else if (extnName.indexOf(RuleEditorData.BASIC_CONSTRAINTS) >=0) { //done
      o = bcPane; 
    } else if (extnName.indexOf(RuleEditorData.AUTH_KEY_ID) >=0) { //done
      o = akiPane; 
    } else if (extnName.indexOf(RuleEditorData.CRL_DIST_POINTS) >= 0) { //done
      o = crlDistPointPane;
    } else if (extnName.indexOf(RuleEditorData.AUTH_INFO_ACCESS) >= 0) { //done
      o = authInfoPane;
    } else if (extnName.indexOf(RuleEditorData.SUBJ_INFO_ACCESS) >= 0) { //done
      o = subjInfoPane;  
    } else if (extnName.indexOf(RuleEditorData.CRL_NUMBER) >=0) { //done
      o = crlNumPane; 
      //} else if (extnName.indexOf("Delta CRL Indicator") >=0) { //done
      //o = deltaCIPane; 
    } else if (extnName.indexOf(RuleEditorData.ISSUING_DIST_POINTS) >=0) { //done
      o = issueDistPointPane; 
    } else if (extnName.indexOf(RuleEditorData.IPADDR_BLOCK) >=0) {
      o = ipaPane;
    } else if (extnName.indexOf(RuleEditorData.AS_ID) >=0) {
      o = asPane;
      //} else if (extnName.indexOf("Router Identifier") >=0) {
      //o = riPane;
    } else if (extnName.indexOf(RuleEditorData.SUBJ_ALT_NAME) >=0) {
      o = sanPane;
    } else if (extnName.indexOf(RuleEditorData.ISSUER_ALT_NAME) >= 0) {
      o = ianPane; 
    } else if (extnName.indexOf(RuleEditorData.CERT_POLICY) >= 0) {
      o = cpPane; 
    } else {// GUI not done yet
      o = null;
    }
    return o;    
  }

  private void initDisplay() {
    boolean buttonOrLabel = true;
    leftPane = new NamePane(myExtnData,
			    myDefault,
			    buttonOrLabel,
			    new Dimension(160, 0),
			    new Dimension(270, 20));
    leftPane.addNameListener(this);
    Dimension dim = new Dimension(280, 300); // 500
    leftPane.setMinimumSize(dim);
    //leftPane.setPreferredSize(dim);
    //leftPane.setMaximumSize(dim);
    splitPane.setLeftComponent(leftPane);

    // prohibt right pane
    JPanel innerPane = RuleUtils.getInnerPane("This extension is prohibited.");
    prohibitPane.add(innerPane);
    prohibitPane.setBorder(new TitledBorder(new EtchedBorder(), "Field Rule"));
    // beginner right pane
    innerPane = RuleUtils.getInnerPane("Select the extension name to set rules.");
    rightPane.add(innerPane);
    rightPane.setBorder(new TitledBorder(new EtchedBorder(), "Field Rule"));
    // under construciton right pane
    innerPane = RuleUtils.getInnerPane("This extension is under construciton.");
    underPane.add(innerPane);
    underPane.setBorder(new TitledBorder(new EtchedBorder(), "Field Rule"));

    leftPane.setBorder(BorderFactory.createRaisedBevelBorder());
    //rightPane.setBorder(BorderFactory.createRaisedBevelBorder());

    splitPane.setRightComponent(rightPane);
    //splitPane.setRightComponent(skiPane);
    setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
    //setBorder(new TitledBorder(new EtchedBorder(), "  " + myType + " Extensions Rule  "));
  }

    public void updateCAInfo()
    {
	//System.out.println("updateCAInfo in extnpane");
	resetContents();
	if (myType == RuleEditorData.CRL_TYPE)
	    issueDistPointPane.resetListFromCA();
	else 
	{
	    asPane.resetListFromCA();
	    ipaPane.resetListFromCA();
	}
	//checkExtensions();
    }

    public void resetContents()
    {
	//System.out.println("reset contents in extnpane");
	if (myType != RuleEditorData.CRL_TYPE)
	{
	    subjInfoPane.resetContents();
	    crlDistPointPane.resetContents();
	    authInfoPane.resetContents();
	}
	else issueDistPointPane.resetContents();
	leftPane.resetPane();
    }

  private String getExtnName(int index) {
    String name = myExtnData[index];

    return name;
  }

    /**  
	 returns true if the extensions contain no errors.
	 returns false if the extensions contain at least one error.

	 calls each check separately so that you get all error messages
    **/
    public boolean checkExtensions()
    {
        boolean sizes = CheckIPASNumBlockSizes();
        boolean asnum = checkASNum();
        boolean ipaddr = checkIPAddr();
        return sizes && asnum && ipaddr;
    }

    public boolean checkASNum()
    {
        Extension extn = findExtension(ExtensionsStatic.id_pe_autonomousSysIds);
        if (extn == null) return true;
        AsNumbersOrRangesInASIdentifierChoice asNumbersOrRanges =
            extn.extnValue.autonomousSysNum.asnum.asNumbersOrRanges;

        if (asNumbersOrRanges.checkASNumber() > 0)
            {
            System.out.println("Bad AS numbers");
            Integer[] list = asNumbersOrRanges.get_Err_list();
	    System.out.println("list of bad AS Numbers is: ");
	    for (int j=0; j< list.length; j++)
		System.out.println("j at " + j + " is " + list[j]);
	    String[]  myVals = asPane.getValues(list);
	    String msg = new String("Errors with the following Autonomous " +
				    "System Numbers:\n");
	    for (int ii = 0; ii< myVals.length; ii++)
		    msg += myVals[ii] + "\n";
            for (int ii = 0; ii < list.length; System.out.print(list[ii++] + " "));
            System.out.println("");
	    JOptionPane.showMessageDialog(null,
					msg,
					"AS Number Range Error",
					JOptionPane.ERROR_MESSAGE);
            return false;
            }
        return true;
        }     
        
    public boolean checkIPAddr()
    {
        Extension extn = findExtension(ExtensionsStatic.id_pe_ipAddrBlocks);
        if (extn == null) return true;
	String msg = new String("");
        IPAddrBlocks ipab = extn.extnValue.ipAddressBlock;
        if (ipab.checkIPAddr() > 0)
            {
            System.out.println("Bad IP Address Blocks");
            Integer[] list = ipab.get_v4ErrList();
            if (list.length > 0)
                {
                System.out.print("V4: ");
                for (int ii = 0; ii < list.length; 
                    System.out.print(list[ii++] + " ")); 
                System.out.println("");
		String[]  myVals =ipaPane.getValues(list, RuleEditorData.IPV4);
		msg += "Errors with the following IPV4 addresses:\n";
		for (int ii = 0; ii< myVals.length; ii++)
		    msg += "\t" + myVals[ii] + "\n";
		msg += "\n";
                }
            list = ipab.get_v6ErrList();
            if (list.length > 0)
                {
                System.out.print("V6: ");
                for (int ii = 0; ii < list.length; 
                    System.out.print(list[ii++] + " "));
                System.out.println("");
		String[]  myVals =ipaPane.getValues(list, RuleEditorData.IPV6);
		msg += "Errors with the following IPV6 addresses:\n";
		for (int ii = 0; ii< myVals.length; ii++)
		    msg += "\t" + myVals[ii] + "\n";
		msg += "\n";
                }
	    showTextDialog(msg,"IP Address Range Error");
	    /*
	    JOptionPane.showMessageDialog(RuleUtils.ruleFrame,
					msg,
					"IP Address Range Error",
					JOptionPane.ERROR_MESSAGE);
	    */
            return false;
            } 
         return true;

         }
    /***
	The purpose of the following routine is to ensure that either
	the ASNumber or IP Address block extension is present with size 
	at least 1.  If the size of one list is zero, the extension will be
	prohibited.  If both are of size zero, the user will be alerted
	to an error in the certificiate.
     ***/
  public boolean CheckIPASNumBlockSizes()
  {
      boolean disableAS = false;
      boolean disableIP = false;
      if (asPane.getListSize() == 0)
      	  disableAS = true;
      if (ipaPane.getCombinedListSize() == 0)
	  disableIP = true;
      /*
      System.out.println("in extn checkblock " + disableAS + " " + disableIP);
      System.out.println("sizes are " + asPane.getListSize() + " " + 
			 ipaPane.getCombinedListSize());
      */
      if (disableAS && disableIP)
      {
	  JOptionPane.showMessageDialog(null,
					"Resource certificate error. " +
					"Either AS Number or IP Address " +
					"Block extension must be present.",
					"Resource Certificate Error",
					JOptionPane.ERROR_MESSAGE);
	  return false;
      }
      for (int i=0; i< myExtnOID.length; i++)
      {
	  if (myExtnOID[i] == ExtensionsStatic.id_pe_autonomousSysIds) 
	   {
	      leftPane.setEnabled(i,!disableAS);
	      if (disableAS)
		  leftPane.setChoice(i,RuleEditorData.PROHIBIT);
	      else if (disableIP)
	      {
		  leftPane.setChoice(i,RuleEditorData.REQUIRE);
		  leftPane.setEnabled(i, false);
	      }
	      else
		  leftPane.setChoice(i,RuleEditorData.ALLOW);
	   }
	  else if (myExtnOID[i] == ExtensionsStatic.id_pe_ipAddrBlocks) 
	   {
	      leftPane.setEnabled(i,!disableIP);
	      if (disableIP)
		  leftPane.setChoice(i,RuleEditorData.PROHIBIT);
	      else if (disableAS)
	      {
		  leftPane.setChoice(i,RuleEditorData.REQUIRE);
		  leftPane.setEnabled(i, false);
	      }
	      else
		  leftPane.setChoice(i,RuleEditorData.ALLOW);
	      
	   }
      }
      //System.out.println("size of asn is " + asPane.getListSize());
      //System.out.println("size of ip is " + ipaPane.getCombinedListSize());
      return true;
  }

    public Extension findExtension(String oid)
        {
        Extensions extns = RuleUtils.cert.cert.toBeSigned.extensions;
        Extension extn = null;
        int i;
        for (i = 0; i < extns.numitems(); i++)
            {
            extn = extns.extension.index(i);
            AsnByteArray objId = new AsnByteArray(extn.extnID.vsize()); 
            extn.extnID.read(objId);             
            if (objId.toString().trim().equals(oid))
                return extn;
            }
        return null;
        }

  public void showTextDialog(String msg, String title)
   {
       dialog = new JDialog();
       dialog.setTitle(title);
       dialog.setModal(true);
       JTextArea jta = new JTextArea(100,20);
       jta.setEditable(false);
       jta.setBackground(Color.white);
       jta.setText(msg);
       JScrollPane jsp = new JScrollPane();
       jsp.setViewportView(jta);
       
       JButton closeButton = new JButton("Close");
       closeButton.setActionCommand("CloseDialog");
       closeButton.addActionListener(this);
       JPanel buttonPanel = new JPanel();
       buttonPanel.add(closeButton);
       JPanel topPane = new JPanel();
       topPane.setLayout(new BoxLayout(topPane, BoxLayout.Y_AXIS));
       topPane.add(jsp);
       topPane.add(buttonPanel);
       dialog.getContentPane().add(topPane);
       dialog.setSize(400,600);
       dialog.setLocation(200,200);
       dialog.setVisible(true);
   }

   public void actionPerformed(ActionEvent e)
    {
	String command = e.getActionCommand();
	if (command.compareToIgnoreCase("CloseDialog") == 0)
	    dialog.dispose();
    }
       
  public void namePerformed(NameEvent e) {
    NamePane np = (NamePane)e.getSource();
    String command = np.getNameCommand();
    String choice = np.getChoice(np.getIndexCommand());
    JPanel pane = null;
    
    //System.out.println("In ExtnPane, command: " + command + ".");  
    if (choice.equals(RuleEditorData.PROHIBIT)) {
      pane = prohibitPane;
    } else {
      pane = (ExtnFieldBasePane)getExtnPane(command);
    }

    if (pane == null) {
      pane = underPane;
    }

    boolean msg = false;
    if (command.equals(RuleEditorData.IPADDR_BLOCK) &&
	(choice.equals(RuleEditorData.PROHIBIT) ||
	 choice.equals(RuleEditorData.ALLOW)))
    {
	if (np.getChoice(RuleEditorData.AS_ID).compareTo(RuleEditorData.PROHIBIT) == 0)
        {
	    msg = true;
	    np.setChoice(np.getIndexCommand(),RuleEditorData.REQUIRE);
	}
	else if (choice.equals(RuleEditorData.PROHIBIT))
        {
	    np.setChoice(RuleEditorData.AS_ID, RuleEditorData.REQUIRE);
	    np.setEnabled(RuleEditorData.AS_ID, false);
	}
	else np.setEnabled(RuleEditorData.AS_ID, true);
	    
    }
    else if (command.equals(RuleEditorData.AS_ID) &&
	   (choice.equals(RuleEditorData.PROHIBIT) ||
	    choice.equals(RuleEditorData.ALLOW)))
    {
	if (np.getChoice(RuleEditorData.IPADDR_BLOCK).compareTo(RuleEditorData.PROHIBIT) == 0)
         {
	    np.setChoice(np.getIndexCommand(),RuleEditorData.REQUIRE);
	    msg = true;
	 }
         else if (choice.equals(RuleEditorData.PROHIBIT))
         {
	    np.setChoice(RuleEditorData.IPADDR_BLOCK, RuleEditorData.REQUIRE);
	    np.setEnabled(RuleEditorData.IPADDR_BLOCK, false);
	 }
	else np.setEnabled(RuleEditorData.IPADDR_BLOCK, true);
    }  
    else if (command.equals(RuleEditorData.AS_ID) &&
	     choice.equals(RuleEditorData.REQUIRE))
	np.setEnabled(RuleEditorData.IPADDR_BLOCK, true);
    else if (command.equals(RuleEditorData.IPADDR_BLOCK) &&
	     choice.equals(RuleEditorData.REQUIRE))
	np.setEnabled(RuleEditorData.AS_ID, true);
    if (msg)
	JOptionPane.showMessageDialog(null,
				      "Either IP Address Blocks or Autonomous"+
				      " System Identifiers must be present " +
				      "in resource certificates.\nIf one is " +
				      "prohibited the other must be required.",
				      "Resource certificate constraint.",
				      JOptionPane.ERROR_MESSAGE);
    //if (command.equals("IP Address Block")) {
    //ipaPane.redraw();
    //} else if (command.equals("Autonomous System ID")) {
    //asPane.redraw();
    //}
    splitPane.setRightComponent(pane);
    
  }

}//  ExtnPane
