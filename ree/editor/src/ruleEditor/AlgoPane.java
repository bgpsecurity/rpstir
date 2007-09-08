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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

abstract class AlgoPane extends FieldBasePane 
implements NameListener {
  public NamePane np;
  private String myTitle = "Signature Algorithm Rule";
  private String[] myName;
  private String[] myNameID;
  private String myType;
  private String myCertType;
  private JFrame frame;
  private JPanel lowerPane;

  public AlgoPane(String[] name, String[] ID, String type, String certType) {
    this("Signature Algorithm Rule", name, ID, type, certType);
  }

  public AlgoPane(String title, String[] name, String[] ID, String type) {
    this(title, name, ID, type, "");
  }

  public AlgoPane(String title, String[] name, String[] ID, String type, String certType) {
    myTitle = title;
    myName = name;
    myNameID = ID;
    myType = type;
    myCertType = certType;
    initDisplay();
  }
  
  public abstract void setupLowerPane(JPanel lowerPane, String myCertType);

  public String getChoice(int i){
    return(np.getChoice(i));
  }

  public void setChoice(int i, String choice){
    np.setChoice(i, choice);
  }

  public int createRule(Member m) {
    boolean hasAllowRequire = false;
    boolean required = false;
    boolean[] used = new boolean[myName.length];
    int i, index;
    String[] choices = new String[myName.length];;
    
    // Check if at least one is selected, aka not prohibit
    for (i = 0; i < myName.length; i++) {
      choices[i] = getChoice(i);
      if (!getChoice(i).equals(RuleEditorData.PROHIBIT)) {
	hasAllowRequire = true;
      }
    }
    if (!hasAllowRequire) {
      JOptionPane.showMessageDialog(frame,
				    "No algorithm set to Allow or Require.\nPlease click on Signature Algorithm field to select the algorithm"); 
      return RuleEditorData.FAILED;
    }	 
        
    m.name.write("Signature Algorithm");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE); 
    m.rule.add();
    RuleChoice rc = m.rule.ref;

    RuleUtils.formAlgoRule(rc, "Signature ", choices, myName, myNameID); 
    
    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) {
    AsnIntRef tagRef = new AsnIntRef();
    AsnByteArray tmpOid; //oid
    String tmp;
    int i, ind = -1, ni = 0;
    int n = myName.length;
    int[] res = new int[n]; // indexing to ThreeWayData
    for (i = 0; i < n; i++) 
        {
	res[i] = 2; // default is prohibit
        }
    if (m.rule == null || m.rule.ref == null || m.rule.ref.definerSeq == null ||
      m.rule.ref.definerSeq.members == null || 
      m.rule.ref.definerSeq.members.numitems() == 0) return true;
    
    Member m1 = m.rule.ref.definerSeq.members.member.index(0);
    if (m1.rule == null || m1.rule.ref == null || m1.rule.ref.definerRule == null)
        return true;
    Rule p = m1.rule.ref.definerRule;//  28
    if (p.targets == null) 
      {
      JOptionPane.showMessageDialog(frame, "No targets in " + myName); 
      return false;
      }
    p.targets.tag(tagRef);
    switch((tagRef.val & ~(AsnStatic.ASN_CONT_CONSTR))) 
      {
    case (RulesStatic.id_allow): // Allow
      if (p.targets.allow != null)
        { 
        ni = p.targets.allow.numitems();
        //System.out.println(" algo allow num: " + ni);
        for (i = 0; i < ni; i++) 
          {
	  tmpOid = new AsnByteArray(200);
          p.targets.allow.target.index(i).objid.read(tmpOid);
          //tmpOid.print();
          tmp = tmpOid.toString();  
          //System.out.println(" algo (allow): \"" + tmp.trim() + "\"");		
          ind = RuleUtils.getOidIndex(myNameID, tmp);
          res[ind] = 1;
          }
        } 
      break;
    case (RulesStatic.id_require):// require, can only have 1 instance 
      if (p.targets.require != null)
        {
        if (p.targets.require.numitems() > 1)
          {
          JOptionPane.showMessageDialog(frame, "Too many required items in " + myName + " rule set"); 
          return false;
          }
        tmpOid = new AsnByteArray(200);
        p.targets.require.target.index(0).objid.read(tmpOid);
        tmp = tmpOid.toString(); 
        //System.out.println(" algo (require): " + tmp);		
        ind = RuleUtils.getOidIndex(myNameID, tmp);
        res[ind] = 0;
        }
      break;
    default:
      JOptionPane.showMessageDialog(frame, "Improper option in " + myName + " rule set"); 
      return false;
      }

    for (i = 0; i < n; i++) 
      {
      np.setChoice(i, RuleEditorData.ThreeWayData[res[i]]); 
      //System.out.println(i + " " + RuleEditorData.ThreeWayData[res[i]]);
      }

    if (ind != -1) 
      {
      disableOtherAlgo(np, ind);
      }
    return true;
    }
  
  public void print() {
    //System.out.println("\n Algorightm Choice: ");
    //np.print();
  }

  public void namePerformed(NameEvent e) {
    int ind = np.getIndexCommand();
    String choice = np.getChoice(ind);
    //System.out.println(" In AlgoPane namePerformed() index: " + ind + " " + choice);

    if (choice == "Require") {
      validateOtherAlgo(np, ind);
    }
    else {
      enableOtherAlgo(np, ind);
    }
  }

  private void initDisplay() {
    if (myName.length == 1) {
      String[] defaultData = new String[1];
      defaultData[0] = RuleEditorData.REQUIRE;
      //System.out.println(" Only one algo.");
      np = new NamePane(myName, defaultData);
    } else {
      np = new NamePane(myName);
    }
    lowerPane = new JPanel();
    setupLowerPane(lowerPane, myCertType);

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    //add(Box.createRigidArea(new Dimension(0,5)));
    add(np);
    np.addNameListener(this);
    add(Box.createRigidArea(new Dimension(0,10)));
    if (myType == "key") {
      add(lowerPane);
      lowerPane.setBorder(BorderFactory.createRaisedBevelBorder());
      add(Box.createVerticalGlue());
    }
    //else {
    //  add(Box.createVerticalGlue());
    //}
    //add(Box.createRigidArea(new Dimension(0,10)));
    //add(Box.createVerticalGlue());
    setBorder(new TitledBorder(new EtchedBorder(), "  " + myTitle + "  "));
  }

  public void disableOtherAlgo(NamePane np, int ind) {
    for (int i = 0; i < np.length(); i++) {
      if (i != ind) {
	np.disableUnit(i);
      }
    }
  }
	
  private void enableOtherAlgo(NamePane np, int ind) {
    for (int i = 0; i < np.length(); i++) {
      if (i != ind) {
	np.enableUnit(i);
      }
    }
  }
  
  private void validateOtherAlgo(NamePane np, int i) {
    boolean stop = false;
    ThreeWayCombo algo;
    String choice;

    for (int ind = 0; ind < np.length(); ind ++) {
      if (ind != i) {
	choice = np.getChoice(ind);
	//System.out.println(" In validateOtherAlgo() index: " + ind + " " + choice);
	if (choice == RuleEditorData.ALLOW) {
	  stop = true;
	  JOptionPane.showMessageDialog(frame,
					"\"Require\" can't coexist with other choices. \n Reset to previous value");
	}
      }
      if (stop)
	break;
    }

    if (stop) {
      np.resetChoice(i);
    } else {
      disableOtherAlgo(np, i);
    }
    
  }
      					

} // AlgoPane

