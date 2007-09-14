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
import name.*;
import asn.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class SubjectPane extends FieldBasePane 
    implements NameListener,
	   RuleListener  {
  //JTextArea textArea;
  String[] nameList;
  JTextField treeText;
  String newline = "\n";
  NamePane np;

  //String[] list;
  private String[] myAttributeName;
  private String[] myDNName;
  private String[] myDNID;
  private String myType;
  private String[] dirStringNames;
  private short[] dirStringTags;
  private ThreeWayCombo[] twc;
  private JTextField[] tf;
  private int numProhibited;

  public SubjectPane(String[] DNName, String[] DNID, String type) {
    this(null, DNName, DNID, type);
  }

  public SubjectPane(String[] attrbuteName, String[] DNName, String[] DNID, String type) {
    myAttributeName = attrbuteName;
    myDNName = DNName;
    myDNID = DNID;
    myType = type;
    numProhibited = 0;
    dirStringNames = new String[4];
    dirStringNames[0] = "Printable String";
    dirStringNames[1] = "Teletex String";
    dirStringNames[2] = "Universal String";
    dirStringNames[3] = "BMP String";
    dirStringTags = new short[4];
    dirStringTags[0] = AsnStatic.ASN_PRINTABLE_STRING;
    dirStringTags[1] = AsnStatic.ASN_T61_STRING;
    dirStringTags[2] = AsnStatic.ASN_UNIVERSAL_STRING;
    dirStringTags[3] = AsnStatic.ASN_BMP_STRING;
    initDisplay();
  }

  private int getIndex(String name) {
    for (int i = 0; i < myDNName.length; i++) {
      if (name.equals(myDNName[i]))
	return i;
    }

    return -1;
  }

  public int createRule(Member M) 
    {
    boolean hasRequire = false;
  //    System.out.println("In subject create rule");
    M.name.write(RuleEditorData.SUBJ_NAME);
    M.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x30
    M.rule.add();
    SetSeqOfRule sso = M.rule.ref.seqOf;
    int i, j;

    Member rdn = sso.member;
    rdn.name.write("RDN");  // RDN
    rdn.tagtype.write(AsnStatic.ASN_SET); //0x31
    rdn.rule.add();
    SetSeqOfRule sso1 = rdn.rule.ref.setOf;
    Member ava = sso1.member;
    ava.name.write("AVA");
    ava.tagtype.write(AsnStatic.ASN_SEQUENCE);
    ava.rule.add();
    RuleChoice rc = ava.rule.ref;
    rc.definerSeq.members.member.index(0).insert();
    Member m1 = rc.definerSeq.members.member.index(0);
    m1.name.write("Permitted AVA OIDs");
    m1.tagtype.write(AsnStatic.ASN_OBJ_ID);
    m1.rule.add();
    Rule ru = m1.rule.ref.definerRule;
    for (i = j = 0; i < myDNName.length; i++)
      {
      if (twc[i].getChoice() == RuleEditorData.PROHIBIT) continue; 
      if (twc[i].getChoice() == RuleEditorData.REQUIRE) hasRequire = true;  
      //System.out.println("index " + i + " " + hasRequire);
      ru.targets.allow.target.index(j).insert();
      Target ta = ru.targets.allow.target.index(j);
      ta.objid.write(RuleUtils.getNameObjID(twc[i].getRuleCommand()));
      }

    rc.definerSeq.members.member.index(1).insert();
    Member m2 = rc.definerSeq.members.member.index(1);
    m2.name.write("AVA Value");
    m2.rule.add();
    Members mm = m2.rule.ref.definedBy;
    for (i = j = 0; i < myDNName.length; i++)
      {
      if (twc[i].getChoice() == RuleEditorData.PROHIBIT) continue; 
      mm.member.index(j).insert();
      Member m21 = mm.member.index(j);
      String str = tf[i].getText().trim();
      m21.name.write(twc[i].getRuleCommand());
      if (twc[i].getRuleCommand() == RuleEditorData.COUNTRY_NAME)
        {
        m21.tagtype.write(AsnStatic.ASN_PRINTABLE_STRING);
        m21.siz.lo.number.write(2);
        m21.siz.hi.number.write(2);
        if (str != null && str.length() > 0)
          {
          m21.rule.add();
          ru = m21.rule.ref.primitive;
          ru.targets.allow.target.index(j).insert();
          Target ta = ru.targets.allow.target.index(j++);
          ta.value.write(str);
          }
        }
      else
        {
        m21.rule.add();            
        Members dsmm = m21.rule.ref.choice;
        for (int k = 0; k < dirStringNames.length; k++)
          {
          dsmm.member.index(k).insert();
          Member dsmem = dsmm.member.index(k);
          dsmem.name.write(dirStringNames[k]);
          dsmem.tagtype.write(dirStringTags[k]);
          if (str != null && str.length() > 0)
            {
            dsmem.rule.add();
            ru = dsmem.rule.ref.primitive;
            ru.targets.allow.target.index(j).insert();
            Target ta = ru.targets.allow.target.index(j++);
            ta.value.write(str);         
            }
          }
        }
      }
    //System.out.println("Start required");
    if (hasRequire)   // group rules for required name parts
      {
      GroupRules grs = sso.groupRules;
      grs.groupRule.index(0).insert();
      GroupRule gr = grs.groupRule.index(0);
      gr.name.write("Required RDNs");
      gr.thencase.rule.add();
      SpecialRule s = gr.thencase.rule.ref.special;
      s.type.write(0x07);  //id-limits
      s.value.limits.location.path.write("dadad");
      for (i = j = 0; i < myDNName.length; i++)
        {
        int min = 0;
        if (twc[i].getChoice() == RuleEditorData.PROHIBIT) continue;
        // System.out.println("Group rule " + i + " state " + twc[i].getChoice()); 
        s.value.limits.valAndLimit.idAndLimit.index(j).insert();
        IdAndLimit il = s.value.limits.valAndLimit.idAndLimit.index(j++);
        il.id.objid.write(myDNID[i]);
        il.max.write(1);
        if (twc[i].getChoice() == RuleEditorData.REQUIRE) min = 1; 
        il.min.write(min);
        // System.out.println("min " + min);
        }         
      }             
    if (M.size() < 0) 
      {
      JOptionPane.showMessageDialog(null, "Error making rules for " +
				       "SubjectName.",
				       "Rule Error", 
				       JOptionPane.ERROR_MESSAGE);	  
      return RuleEditorData.FAILED;
      }      
    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member M) 
    {
    int i, j;
    //System.out.println("Set Rule for " + RuleEditorData.SUBJ_NAME);
    if (M.rule == null || M.rule.ref == null ||
        M.rule.ref.seqOf == null || M.rule.ref.seqOf.member == null) return true;
    Member rdn = M.rule.ref.seqOf.member;
    if (rdn.rule == null || rdn.rule.ref == null || rdn.rule.ref.setOf == null ||
        rdn.rule.ref.setOf.member == null) return true;
    Member ava = rdn.rule.ref.setOf.member;
    if (ava.rule == null || ava.rule.ref == null) return true;
    RuleChoice rc = ava.rule.ref;
    if (rc.definerSeq == null || rc.definerSeq.members == null ||
        rc.definerSeq.members.numitems() == 0) return true;
    Member m1 = rc.definerSeq.members.member.index(0);
    if (m1.rule == null || m1.rule.ref == null || 
        m1.rule.ref.definerRule == null) return true;
    Rule ru = m1.rule.ref.definerRule;
    if (ru.targets == null || ru.targets.allow == null ||
        ru.targets.allow.numitems() == 0) return true;
    for (i = 0; i < myDNName.length; i++)
      {    
      twc[i].setChoice(RuleEditorData.PROHIBIT);
      tf[i].setText("");
      }
    for (i = 0; i < myDNName.length; i++)
      {   
      for (j = 0; j < ru.targets.allow.numitems(); j++)
        {  
        Target ta = ru.targets.allow.target.index(j); 
        AsnByteArray aba  = new AsnByteArray();
        ta.objid.read(aba);
        if (twc[i].getRuleCommand().compareTo(RuleUtils.getObjIDname(aba.toString())) == 0)
          {
          twc[i].setChoice(RuleEditorData.ALLOW);          
          break;
          }
        }
      }
    if (rc.definerSeq.members.numitems() < 2) return true;
    Member m2 = rc.definerSeq.members.member.index(1);
    if (m2.rule == null || m2.rule.ref == null || m2.rule.ref.definedBy == null)
      return true;
    Members mm = m2.rule.ref.definedBy;
    if (M.rule.ref.seqOf.groupRules == null) return true;
    GroupRules grs = M.rule.ref.seqOf.groupRules;
    for (j = 0; j < grs.numitems(); j++)
      {
      GroupRule gr = grs.groupRule.index(j);
      if (gr.thencase == null || gr.thencase.rule == null ||
        gr.thencase.rule.ref == null || gr.thencase.rule.ref.special == null)
        continue;
      SpecialRule s = gr.thencase.rule.ref.special;
      int kk;
      if (s.value == null || s.value.limits == null || 
        s.value.limits.valAndLimit == null || 
        s.value.limits.valAndLimit.idAndLimit == null ||
        (kk = s.value.limits.valAndLimit.numitems()) == 0) continue;
      for (int k = 0; k < kk; k++)
        {
        // System.out.println(k + " out of " + kk);
        IdAndLimit il = s.value.limits.valAndLimit.idAndLimit.index(k);
        if (il.id == null || il.id.objid == null) continue;
        String requireAllow;
        if (il.min == null || il.min.size() == 0) 
          requireAllow = RuleEditorData.ALLOW;
        else requireAllow = RuleEditorData.REQUIRE;
        AsnByteArray aba = new AsnByteArray();
        il.id.objid.read(aba);
        for (i = 0; i < myDNName.length; i++)
          {
          if (twc[i].getRuleCommand().
            compareTo(RuleUtils.getObjIDname(aba.toString())) == 0)
            {
            twc[i].setChoice(requireAllow);          
            break;
            }
          }
        }
      }
    return true;
    }

  public void namePerformed(NameEvent e) {
      /*NamePane np = (NamePane)e.getSource();
     String command = np.getNameCommand();
    String ufn = RuleUtils.getDNufn(command);
    System.out.println(" namePerformed: " + command + " " + ufn + ".");
    subtreePane.insertString(ufn);*/
  }

  public void setLastToRequire()
  {
      if (numProhibited == myDNName.length -1)
      {
	  for (int index = 0; index < myDNName.length; index++)
	  {
	      if (twc[index].getChoice() == RuleEditorData.ALLOW)
		  twc[index].setChoice(RuleEditorData.REQUIRE);
	  }
      }
  }

  public void rulePerformed(RuleEvent e) {
      //String command = ((ThreeWayCombo)e.getSource()).getRuleCommand();
      //System.out.println("command is " + command);
      if ( (tf == null) || (twc == null))
	  return;  // display not yet initialized
      
      String choice = ((ThreeWayCombo)e.getSource()).getChoice();
      //System.out.println("choice is " + choice);
      int i =  ((ThreeWayCombo)e.getSource()).getIndexCommand();
      //System.out.println("i is " + i + "size is " + tf.length);
      if (choice.compareToIgnoreCase("prohibit") == 0)
      {
	  if (tf[i].isEnabled())
	  {
	    if (numProhibited < myDNName.length - 1)
	    {
		tf[i].setText("");
		tf[i].setEnabled(false);
		numProhibited++;
		if (numProhibited == myDNName.length -1)
		    setLastToRequire();
	    }
	    else
	    {
	      JOptionPane.showMessageDialog(null,"Cannot prohibit all fields.",
					    "Prohibit limit exceeded",
					    JOptionPane.WARNING_MESSAGE);
	      twc[i].setChoice(RuleEditorData.REQUIRE);
	    }
	  }
      }
      else
      {
	  if (!tf[i].isEnabled()) numProhibited--;
	  tf[i].setEnabled(true);
	  setLastToRequire();
      }
	  
  }


  public void checkStatus() {
  }

  public void setEnabled(boolean b) {
  }
  
  private void initDisplay() {
    Dimension dim;

    setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
    // System.out.println("init display of subjectpane");
    JPanel jp;
    //JTextField tf;
    //ThreeWayCombo twc;

    JPanel rightPane = new JPanel();
    rightPane.setLayout(new BoxLayout(rightPane,BoxLayout.Y_AXIS));
    rightPane.add(Box.createVerticalGlue());
    if (myDNName.length > 0)
    {
	twc = new ThreeWayCombo[myDNName.length];
	tf = new JTextField[myDNName.length];
    }
    else
    {
	twc=null;
	tf=null;
	return;
    }

    for (int i=0; i< myDNName.length; i++)
    {
	//System.out.println("SubjPane: " + 
	//		   "create name for index " + i + "--" + myDNName[i]);
	jp = new JPanel();
	//jp.setLayout(new BoxLayout(jp,BoxLayout.X_AXIS));
	tf[i] = new JTextField(15);
	tf[i].setMaximumSize(new Dimension(20,25));
	twc[i] = new ThreeWayCombo(myDNName[i],false);
	twc[i].setRuleCommand(myDNName[i]);
	twc[i].setIndexCommand(i);
	twc[i].addRuleListener(this);
	jp.add(twc[i]);
	jp.add(tf[i]);
	jp.add(Box.createRigidArea(new Dimension(20,0)));
	rightPane.add(jp);
    }
    rightPane.add(Box.createVerticalGlue());
    add(rightPane);
    
    setBorder(new TitledBorder(new EtchedBorder(), "  Subject Name Rule  "));

    if (RuleUtils.cert == null)
    {
	RuleUtils.cert = new RenderCA();
	RuleUtils.cert.newCA(true, false);
    }
  }

  public void redraw() {
  }

    public void resetPane()
    {
	for (int i = 0; i< myDNName.length; i++)
	{
	    tf[i].setText("");
	    twc[i].setChoice(RuleEditorData.ALLOW);
	}
    }
} // SubjectPane
	

