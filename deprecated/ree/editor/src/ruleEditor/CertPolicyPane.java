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
import name.*;
import extensions.*;

import java.io.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class CertPolicyPane extends ExtnFieldBasePane 
{
  private String myName = "Certificate Policy";
  private String[] names;
  private String[] ids;
  private NamePane np;
  private JSplitPane splitPane;
  private JPanel bottomPane;// = new JPanel();
  private JPanel prohibitPane;// = new JPanel();
  private JPanel anyPane; // = new JPanel();
  private ThreeWayCombo cps;
  JLabel labelCps;
  private ThreeWayCombo userNotice;
  private ThreeWayCombo noticeRef;
  JLabel labeOrg;
  JLabel labelNN;
  private ThreeWayCombo explicitText;
  JLabel textLabel;
  private String cpsChoice = RuleEditorData.ALLOW;
  private String userNoticeChoice = RuleEditorData.ALLOW;
  private String noticeRefChoice = RuleEditorData.ALLOW;
  private String explicitTextChoice = RuleEditorData.ALLOW;
  private JTextField noticeNumbers;
  private String nns;
    //static final String fileName = "certPolicy";
  private Vector vName;
  private Vector vID;
  private JFrame frame;

  public CertPolicyPane(String type) {
    super("Certificate Policy", RuleEditorData.REQUIRE, type);
  }

  // NOTE:  For all the configured policy ID, there is NO
  // policy qualifier allowed.  So far only ANYPOLICY has qualifier
  // Later, if this assumption changes, setRule() needs attention as well.
  private String[] getPolicyNames() {
    vName = new Vector();
    vID = new Vector();
    int temp, ni;

    vName.addElement("ResourceCertificatePolicy");
    vID.addElement("1.3.6.1.5.5.7.14.2");
    
    ni = vID.size();
    names = new String[ni];
    ids = new String[ni];
    for (int i = 0; i < ni; i++) {
      names[i] = (String)vName.elementAt(i);
      ids[i] = (String)vID.elementAt(i);
    }

    return names;
  }

  public void setContentPane() {
    names = getPolicyNames();
    np = new NamePane(names, false); // no button
    //np.addNameListener(this);
    np.setChoice(0, RuleEditorData.REQUIRE, true);
   
    contentPane.add(np);
  }

  public int createRule(Member M) {
    int i;
    int lth;
    int ind, index;
    int indQ = -1;
    int indN = -1;
    AsnByteArray out = new AsnByteArray(500);
    Rule p;
    boolean hasRequire = false;
    boolean hasAllowRequire = false;
    String critical = RuleEditorData.ALLOW;

    for (i = 0; i < names.length; i++) {      
      if (!np.getChoice(i).equals(RuleEditorData.PROHIBIT)) {
	if (np.getChoice(i).equals(RuleEditorData.REQUIRE)) {
	  hasRequire = true;
	}
	hasAllowRequire = true;
      }
    }
    if (!hasAllowRequire) { // no extensions requested
      return RuleEditorData.SUCCESS;
    }
    
    M.name.write(myName);
    M.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x30
    M.rule.add();
    SetSeqOfRule sso = (SetSeqOfRule)M.rule.ref.seqOf;
    sso.member.name.write("Policy Information");
    sso.member.tagtype.write(AsnStatic.ASN_SEQUENCE);
    sso.member.rule.add();
    RuleChoice rc = sso.member.rule.ref;

    rc.definerSeq.members.member.index(0).insert();
    Member m1 = (Member)rc.definerSeq.members.member.index(0);
    m1.name.write("Permitted Policy IDs");
    m1.tagtype.write(AsnStatic.ASN_OBJ_ID); //0x06
    m1.rule.add();
    p = (Rule)m1.rule.ref.definerRule;// Rule 

    index = -1;
    for (i = 0; i < ids.length; i++) {      
      if (!np.getChoice(i).equals(RuleEditorData.PROHIBIT)) {
	p.targets.allow.target.index(++index).insert();
	((Target)p.targets.allow.target.index(index)).objid.write(ids[i]);
      }
    }
    if ((lth = M.encode(out)) < 0) { // In real production this should not happen
      System.out.println("cert policy OID encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } else {
      //System.out.println("cert policy OID succeed"); 
    }
    out = null;

    out = new AsnByteArray(500);
    if ((lth = M.encode(out)) < 0) { // In real production this should not happen
      System.out.println("cert policy group rule 1 encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    } else {
      //System.out.println("cert policy group rule 1 succeed"); 
    }
//    M.put_file("junk");
    out = null;
    
    return RuleEditorData.SUCCESS;
  }

  private void addDisplayMember(Members ms, int index, int tagtype) {
    ms.member.index(index).insert();
    Member m = ms.member.index(index); 
    m.tagtype.write(tagtype);
    m.siz.lo.number.write(1);
    m.siz.hi.number.write(200);

  }

  private int getOidIndex(String oid) {
    for (int i = 0; i < vID.size(); i++) {
      if (vID.elementAt(i).equals(oid)) {
	return i;
      }
    }
    return -1;
  }

  private String getOidName(String oid) {
    int ind = getOidIndex(oid);
    return((String)vName.elementAt(ind));
  }

  public boolean setRule(Member m) {
    AsnIntRef tagRef = new AsnIntRef();
    AsnIntRef intRef = new AsnIntRef();
    AsnByteArray tmpOid; //oid
    String tmp, nnStr = new String();
    int i, ni, ind, n = vID.size();
    int[] res = new int[n];
    for (i = 0; i < n; i++) {
	res[i] = 2; // default is prohibit
    }

    SetSeqOfRule sso = (SetSeqOfRule)m.rule.ref.seqOf;
    RuleChoice rc = sso.member.rule.ref;
    Member m1 = (Member)rc.definerSeq.members.member.index(0);
    Rule p = (Rule)m1.rule.ref.definerRule;// Rule 

    // Get allowed policy ID
    ni = p.targets.allow.numitems();
    System.out.println("n is " + n + " ni is " + ni);
    //System.out.println(" Policy allow num: " + ni);
    for (i = 0; i < ni; i++) {
      tmpOid = new AsnByteArray(200);
      p.targets.allow.target.index(i).objid.read(tmpOid);
      //tmpOid.print();
      tmp = tmpOid.toString();  
      //System.out.println(" policy (allow): \"" + tmp.trim() + "\"");		
      ind = getOidIndex(tmp);
      System.out.println("oid index is " + ind);
      res[ind] = 1; //allow
    }
    
    if (!(res[0] == 2)) {// any policy not prohibit          
      // policy qualifier
      Member m2 = (Member)rc.definerSeq.members.member.index(1);
      Members m21 = (Members)m2.rule.ref.definedBy;// CompoundRule 

      // We are only interested in AnyPolicy's qualifier
      Member m211 = (Member)m21.member.index(0);
      SetSeqOfRule sso1 = (SetSeqOfRule)m211.rule.ref.seqOf;
      RuleChoice rc1 = sso1.member.rule.ref;
      Member mm1= (Member)rc1.definerSeq.members.member.index(0);
      p = (Rule)mm1.rule.ref.definerRule;
      ni = p.targets.allow.numitems();
      cpsChoice = RuleEditorData.PROHIBIT;
      userNoticeChoice = RuleEditorData.PROHIBIT;
      for (i = 0; i < ni; i++) {
	tmpOid = new AsnByteArray(200);
	p.targets.allow.target.index(i).objid.read(tmpOid);
	tmp = tmpOid.toString();  
	//System.out.println(" qualifier (allowed): \"" + tmp.trim() + "\"");
	if (tmp.equals(ExtensionsStatic.id_pkix_cps)) {
	  cpsChoice = RuleEditorData.ALLOW;
	}
	if (tmp.equals(ExtensionsStatic.id_pkix_unotice)) {
	  userNoticeChoice = RuleEditorData.ALLOW;
	}
      }
 
      Member mm2 = (Member)rc1.definerSeq.members.member.index(1);
      Members mm21 = (Members)mm2.rule.ref.definedBy;// CompoundRule 26
      ind = -1;
      if (cpsChoice.equals(RuleEditorData.ALLOW)) {
	++ind;
      }
      if (userNoticeChoice.equals(RuleEditorData.ALLOW)) {
	Member mm212 = (Member)mm21.member.index(++ind);//user notice
	Members ms = mm212.rule.ref.sequence.members;
	int indN = -1;
	noticeRefChoice = RuleEditorData.PROHIBIT;
	explicitTextChoice = RuleEditorData.PROHIBIT;
	ni = ms.numitems();
	for (i = 0; i < ni; i++) {
	  Member ms1 = ms.member.index(i);
	  AsnByteArray aba = new AsnByteArray();
	  ms1.name.read(aba);
	  if (aba.toString().equals("Notice Reference")) {
	    noticeRefChoice = RuleEditorData.ALLOW;
	    ms1.optional.read(intRef);
	    if (intRef.val == AsnStatic.ASN_BOOL_TRUE) {
	      noticeRefChoice = RuleEditorData.REQUIRE;
	    }
	    Member ms12 = ms1.rule.ref.sequence.members.member.index(1);
	    Member ms121 = ms12.rule.ref.seqOf.member;
	    Rule r = ms121.rule.ref.primitive;
	    Targets ts = r.targets.allow;
	    int nn = ts.numitems();
	    intRef = new AsnIntRef();
	    for (int j = 0; j < nn; n++) {
	      ts.target.index(j).num.read(intRef);
	      nnStr = nnStr + intRef.val;
	    }	    
	  } else { // explicit text
	    explicitTextChoice = RuleEditorData.ALLOW;
	    ms1.optional.read(intRef);
	    if (intRef.val == AsnStatic.ASN_BOOL_TRUE) {
	      explicitTextChoice = RuleEditorData.REQUIRE;
	    }
	    
	  }
	}
      }
      
    }

    // get required policy
    GroupRule gr = sso.groupRules.groupRule.index(0);
    SpecialRule s = gr.thencase.rule.ref.special;
    ni = s.value.limits.valAndLimit.numitems();
    for (i = 0; i < ni; i++) {
      tmpOid = new AsnByteArray(200);
      s.value.limits.valAndLimit.idAndLimit.index(i).id.objid.read(tmpOid);
      tmp = tmpOid.toString();  
      //System.out.println(" policy (required): \"" + tmp.trim() + "\"");		
      ind = getOidIndex(tmp);
      res[ind] = 0;
    }
    // set policy id choice
    for (i = 0; i < ids.length; i++) {
      np.setChoice(i, RuleEditorData.ThreeWayData[res[i]]);
    }

    // set choices and values
    cps.setChoice(cpsChoice);
    userNotice.setChoice(userNoticeChoice);
    noticeRef.setChoice(noticeRefChoice);
    noticeNumbers.setText(nnStr);
    explicitText.setChoice(explicitTextChoice);
    return true;
  }

}
