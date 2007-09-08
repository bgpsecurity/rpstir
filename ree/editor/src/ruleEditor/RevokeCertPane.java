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

public class RevokeCertPane extends ExtnBasePane
  {
  String myName = RuleEditorData.REVOKED_CERTS;
  String myType;
    //private JSplitPane splitPane = new JSplitPane();
  NamePane np;

  String[] name = {
    "User Certificate Number",
    "Revocation Date",
  };

  String[] myDefault = {
    RuleEditorData.REQUIRE, // "User Certificate Serial Number",
    RuleEditorData.REQUIRE, // "Revocation Date",
  };


  public RevokeCertPane(String type) {
    super(RuleEditorData.REVOKED_CERTS);
    myType = type;
    //setSplitPane(splitPane);
    //reasonCodePane = new ReasonCodePane(myType);
    //if (init())
    //  System.exit(0);
    initDisplay();
  }


  private void initDisplay() {
    Dimension dim;
    String[] fDefault;

    fDefault = myDefault;
     
    np = new NamePane(name, 
		      fDefault,
		      false, // not a button 
		      new Dimension(140, 0), 
		      new Dimension(440, 0));  
      
    np.setTitle("RC Fields");
    dim = new Dimension(300, 150);
    np.setMinimumSize(dim);
    np.setPreferredSize(dim);
    //np.setMaximumSize(dim);
    np.setAlignmentX(Component.TOP_ALIGNMENT); 
   
    //JPanel leftPane = new JPanel();
    //leftPane.setLayout(new BoxLayout(leftPane, BoxLayout.Y_AXIS));
    //leftPane.add(np);

    add(np);
    //splitPane.setLeftComponent(leftPane);
    //splitPane.setRightComponent(rightPane);
    //setLayout(new BoxLayout(this, BoxLayout.X_AXIS));

  }

  public int createRule(Member m) 
    {
    int i, lth, ind = -1;

    m.name.write(myName);  // Revoked Certificates
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.optional.write(AsnStatic.ASN_BOOL_TRUE);  // absent if empty
    m.rule.add();
    SetSeqOfRule sso = m.rule.ref.seqOf;
    sso.min.write(1);  // must be absent if empty
    sso.member.name.write(RuleEditorData.REVOKED_CERT);
    sso.member.tagtype.write(AsnStatic.ASN_SEQUENCE);
    sso.member.rule.add();
    CompoundRule cr = sso.member.rule.ref.sequence;
    cr.members.member.index(++ind).insert();
    Member m1 = (Member)cr.members.member.index(ind);
    m1.name.write("User Certificate Serial Number");
    m1.tagtype.write(AsnStatic.ASN_INTEGER); //0x06

    cr.members.member.index(++ind).insert();
    Member m2 = (Member)cr.members.member.index(ind);
    m2.name.write("Revocation Date");
    m2.tagtype.write(AsnStatic.ASN_UTCTIME); //0x17
    m2.rule.add();
    DateRule d = (DateRule)m2.rule.ref.date;// DateRule 
    d.min.write(-120);  // dummy limit of 10 yrs ago
    d.momin.write(AsnStatic.ASN_BOOL_TRUE);  // 120 is in months
    d.max.write(0);  // not after now
    d.ref.write(""); // Reference to current time
  /*  if ((lth = m.size(out)) < 0) 
       // In real production this should not happen
	System.out.println(" encode out = " + lth + " " + AsnErrorMap.asn_map_string);
    else System.out.println("Revocation Date succeed"); */
    
    return RuleEditorData.SUCCESS;    
  }

  public boolean setRule(Member m) {
      //System.out.println(" In RevokeCertPane.  setRule()");
    return true;
 /*
    AsnIntRef tagRef = new AsnIntRef();
    AsnByteArray tmpOid; //oid
    String tmp;
    int i, ni, ind;
    //int n = extnOID.length;
    //int[] res = new int[n]; // indexing to ThreeWayData

    for (i = 0; i < n; i++) {
	res[i] = 0; // default is prohibit
    }
    
    // get CRL entry extns
    Member mm = (Member)m.rule.ref.seqOf.member.rule.ref.sequence.members.member.index(2);
    // get allowed extn ID
    if (mm.rule.ref != null) {
      SetSeqOfRule sso = (SetSeqOfRule)mm.rule.ref.seqOf;
      RuleChoice rc = sso.member.rule.ref;
      Member m1 = (Member)rc.definerSeq.members.member.index(0);
      Rule p = (Rule)m1.rule.ref.definerRule;// Rule 
      
      // get allowed extn ID
      ni = p.targets.allow.numitems(); // only allowed extn here
      //System.out.println(" CRL entry extn allow num: " + ni);
      for (i = 0; i < ni; i++) {
	tmpOid = new AsnByteArray(200);
	p.targets.allow.target.index(i).objid.read(tmpOid);
	//tmpOid.print();
	tmp = tmpOid.toString();  
	//System.out.println(" crl entry extn (allow): \"" + tmp.trim() + "\"");
	ind = RuleUtils.getOidIndex(extnOID, tmp);
	res[ind] = 1;
      } 
      for (i = 0; i < n; i++) {
	extnPane.setChoice(i, RuleEditorData.ThreeWayData[res[i]]); 
	//System.out.println(i + " " + RuleEditorData.ThreeWayData[res[i]]);
      }
      
      // get critical flag
      Member m2 = (Member)rc.definerSeq.members.member.index(1);
      Members m21 = (Members)m2.rule.ref.definedBy;// CompoundRule 26
      ni = m21.numitems();
      for (i = 0; i < ni; i++) {
	ExtnFieldBasePane o = getCrlExtnPane(i);
	if (o != null) { 
	  Member m211 = (Member)m21.member.index(i);
	  if (m211.rule.ref == null) { // prohibit, mustnotcritical
	    o.setCriticality(RuleEditorData.PROHIBIT);
	  } else { // Allow and Require
	    p = m211.rule.ref.primitive;
	    p.targets.tag(tagRef); 
	    switch((tagRef.val & ~(AsnStatic.ASN_CONT_CONSTR))) 
              {
	    case RulesStatic.id_allow: // Allow, maybe critical
	      o.setCriticality(RuleEditorData.ALLOW);
	      break;
	    case RulesStatic.id_require // require, must be critical
	      o.setCriticality(RuleEditorData.REQUIRE);
	      break;
            default:
              JOptionPane.showMessageDialog(frame, "Invalid choice in " + myName + " rule set"); 
              return false;
	    }
	    
	  }
	}
      }
      
      // get rule
      Member m3 = (Member)rc.definerSeq.members.member.index(2);    
      Members m31 = m3.rule.ref.wrapper.rule.ref.definedBy;
      ni = m31.numitems();
      for (i = 0; i < ni; i++) { 
	ExtnFieldBasePane o = getCrlExtnPane(i);
	if (o != null) { 
	  Member m311 = (Member)m31.member.index(i);
	  o.setRule(m311);
	}
      }
      
      // get required extn
      GroupRule gr = sso.groupRules.groupRule.index(0);
      if (gr.thencase.rule.ref != null) {
	SpecialRule s = gr.thencase.rule.ref.special;
	
	ni = s.value.limits.valAndLimit.numitems();
	for (i = 0; i < ni; i++) {
	  tmpOid = new AsnByteArray(200);
	  s.value.limits.valAndLimit.idAndLimit.index(i).id.objid.read(tmpOid);
	  tmp = tmpOid.toString();  
	  //System.out.println(" extn (required): \"" + tmp.trim() + "\"");		
	  ind = RuleUtils.getOidIndex(extnOID, tmp);
	  res[ind] = 0;
	}    
      }
    }
*/
  }


}
