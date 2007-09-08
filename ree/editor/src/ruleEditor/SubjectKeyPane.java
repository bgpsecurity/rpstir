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

public class SubjectKeyPane extends AlgoPane 
{
  private JFrame frame;
  String myTitle = "Public Key Algorithm Rule";
  String[] myData;
  String[] myID;
  private int loKeySize = 1024;
  private int hiKeySize = 1024;
  private JTextField hiText;
  private JTextField loText;
  
  public SubjectKeyPane(String[] data, String[] ID, String certType) {
    super("Public Key Algorithm Rule", data, ID, "key", certType);
    myData = data;
    myID = ID;
  }

  private void formUnitPane(JPanel pane,
			    JLabel label,
			    JTextField text) {
    pane.add(label);
    pane.add(text);
    text.setPreferredSize(RuleEditorData.shortField);
    text.setMinimumSize(RuleEditorData.shortField);
    text.setMaximumSize(RuleEditorData.shortField);
    //text.addActionListener(this);

  }
  public void setupLowerPane(JPanel lowerPane, String certType){
    // setup key size and parameter
    JLabel label = new JLabel("Please enter the key size: ");
    JLabel loLabel = new JLabel("Min: ");
    JLabel hiLabel = new JLabel("Max: ");
    loText = new JTextField();
    //loText.setActionCommand("low");
    hiText = new JTextField();
    //hiText.setActionCommand("high");
    
    JPanel loP = new JPanel();
    JPanel hiP = new JPanel();
    formUnitPane(loP, loLabel, loText);
    formUnitPane(hiP, hiLabel, hiText);

    //System.out.println("type: " + certType);

    Dimension dim = new Dimension(900, 100);
    lowerPane.setMinimumSize(dim);
    lowerPane.setPreferredSize(dim);
    lowerPane.setMaximumSize(dim);
    lowerPane.setLayout(new BoxLayout(lowerPane, BoxLayout.Y_AXIS));
    lowerPane.add(Box.createRigidArea(new Dimension(0,5)));
    lowerPane.add(label);
    //lowerPane.add(Box.createRigidArea(new Dimension(0,5)));
    lowerPane.add(loP);
    //lowerPane.add(Box.createRigidArea(new Dimension(0,5)));
    lowerPane.add(hiP);
    //lowerPane.add(Box.createVerticalGlue());

    loText.setText("1024");
    hiText.setText("1024");
  }

  public int createRule(Member m) {
    boolean hasAllowRequire = false;
    boolean required = false;
    String[] choices = new String[myData.length];;
    int i, index;

    // read min/max values from text fields
    loKeySize = Integer.parseInt(loText.getText().trim());
    hiKeySize = Integer.parseInt(hiText.getText().trim());
    // check key values
    String msg = new String();
    if (loKeySize < 1024)
	msg += "Minimum key size is 1024 bits.\n";
    if (hiKeySize < loKeySize)
	msg += "Maximum key size must be greater than minimum key size.\n";
    if (msg.length() > 1)
    {
	JOptionPane.showMessageDialog(null, "Error in Subject Public Key\n\n" +
				      msg, 
				      "Subject Public Key Size Error",
				      JOptionPane.ERROR_MESSAGE);
	loText.setText(Integer.toString(1024));
	hiText.setText(Integer.toString(1024));
	return RuleEditorData.FAILED;
    }
    // Check 
    for (i = 0; i < myData.length; i++) {
      choices[i] = getChoice(i);      
      if (!getChoice(i).equals(RuleEditorData.PROHIBIT)) {
	hasAllowRequire = true;
 	if (getChoice(i).equals(RuleEditorData.REQUIRE)) {
	  required = true;
	}
      }
    }
    if (!hasAllowRequire) { // no algorithm allowed
      JOptionPane.showMessageDialog(frame,
				    "No algorithm set to Allow or Require.\nPlease click on Subject Public Key field to select the algorithm"); 

      return RuleEditorData.FAILED;
    }	 

    m.name.write("Subject Public Key");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x30
    m.rule.add();
    RuleChoice rc = m.rule.ref;
    rc.definerSeq.members.member.index(0).insert();

    Member m1 = (Member)rc.definerSeq.members.member.index(0);
    m1.name.write("Algorithm");
    m1.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x30
    m1.rule.add();
    RuleChoice rc1 = m1.rule.ref;

    RuleUtils.formAlgoRule(rc1, "", choices, myData, myID);

    // Add Public key field
    rc.definerSeq.members.member.index(1).insert();
    Member m2 = (Member)rc.definerSeq.members.member.index(1);
    m2.name.write("Public Key");
    m2.tagtype.write(AsnStatic.ASN_BITSTRING); //0x3
    m2.rule.add();
    m2.rule.ref.wrapper.rule.add(); //wrapper

    for (i = 0, index = -1; i < choices.length; i++) {
      if (choices[i].equals(RuleEditorData.ALLOW) || 
	  choices[i].equals(RuleEditorData.REQUIRE)) {

	m2.rule.ref.wrapper.rule.ref.definedBy.member.index(++index).insert(); //26
	Member m21 = m2.rule.ref.wrapper.rule.ref.definedBy.member.index(index);
	if (myData[i].equals("secsig-RSA:") ||
	    myData[i].equals("rsadsi-rsaEncryption")) 
          {
	  m21.name.write("SubjectPublicKeyInfo - RSA");
	  m21.tagtype.write(AsnStatic.ASN_SEQUENCE); //0x30
	  m21.rule.add();
	  
	  m21.rule.ref.sequence.members.member.index(0).insert();
	  Member m211 = m21.rule.ref.sequence.members.member.index(0);
	  m211.name.write("modulus");
	  m211.tagtype.write(AsnStatic.ASN_INTEGER);
            // modulus must start with 0 in the 0x80 bit of first byte
            // therefore bump up 1 if exactly a multiple of 8 bits
	  m211.siz.lo.number.write((loKeySize/8) + 1); 
	  m211.siz.hi.number.write((hiKeySize/8) + 1);    
	  m21.rule.ref.sequence.members.member.index(1).insert();
	  Member m212 = m21.rule.ref.sequence.members.member.index(1); //exponent
	  m212.name.write("public exponent");
	  m212.tagtype.write(AsnStatic.ASN_INTEGER);
          m212.rule.add();
          Targets trgts = m212.rule.ref.primitive.targets.require;
          trgts.target.index(0).insert();
          Target ta = trgts.target.index(0);
          ta.num.write(0x010001);
	  }
        else if (myData[i].equals("secsig-DSA:") ||
		   myData[i].equals("secsig-DSA-Common:") ||
		   myData[i].equals("dsa:")) {

	  m21.name.write("SubjectPublicKeyInfo - DSA");
	  m21.tagtype.write(AsnStatic.ASN_INTEGER); //0x2
	  m21.siz.lo.number.write(loKeySize/8);
	  m21.siz.hi.number.write(hiKeySize/8 + 1);    
	}
      }
    }

    return RuleEditorData.SUCCESS;
  }

  public boolean setRule(Member m) 
    { 
    AsnIntRef tagRef = new AsnIntRef();
    AsnByteArray tmpOid; //oid
    String tmp;
    int i, ni = 0, ind = -1;
    int n = myID.length;
    String[] res = new String[n];

    for (i = 0; i < n; res[i++] = RuleEditorData.PROHIBIT); 

    //System.out.println("n is " + n);
    //for (int p=0; p<n; p++)
    //	System.out.print("my id " + myID[p]);
    // get allowed algo 

    if (m != null && m.rule != null && m.rule.ref != null &&
      m.rule.ref.definerSeq != null && m.rule.ref.definerSeq.members != null)
      {
      Member m1 = m.rule.ref.definerSeq.members.member.index(0); // Algorithm
      if (m1 != null && m1.rule.ref != null && m1.rule.ref.definerSeq != null &&
       m1.rule.ref.definerSeq.members != null)
        {
        Member m11 = m1.rule.ref.definerSeq.members.member.index(0); //  Alg OID
        if (m11 != null && m11.rule != null && m1.rule.ref != null &&
          m1.rule.ref.definerRule != null)
          {
          Rule p = m11.rule.ref.definerRule;// Plain Rule
          if (p.targets != null)
            {        
            p.targets.tag(tagRef);
            switch((tagRef.val & ~(AsnStatic.ASN_CONT_CONSTR)))  
              {
            case RulesStatic.id_allow:
              if (p.targets.allow != null)
                {  
                ni = p.targets.allow.numitems();
                //System.out.println(" DN allow num: " + ni);
                for (i = 0; i < ni; i++)  
                  {
                  tmpOid = new AsnByteArray(200);
                  p.targets.allow.target.index(i).objid.read(tmpOid);
                  //tmpOid.print();
                  tmp = tmpOid.toString();  
                  //System.out.println(" algo (allow): \"" + tmp.trim() + "\"");		
                  ind = RuleUtils.getOidIndex(myID, tmp);
                  res[ind] = RuleEditorData.ALLOW;
                  }
                } 
              break;
            case RulesStatic.id_require: // require, can only have 1 instance
              tmpOid = new AsnByteArray(200);
              if (p.targets.require != null)
                {
                if (p.targets.require.numitems() > 1)
                  {
                  JOptionPane.showMessageDialog(frame, 
                      "too many requires in " + "SubjectPublicKey"); 
                  return false;
                  }
                p.targets.require.target.index(0).objid.read(tmpOid);
                tmp = tmpOid.toString(); 
                //System.out.println(" algo (require): " + tmp);		
                ind = RuleUtils.getOidIndex(myID, tmp);
                res[ind] = RuleEditorData.REQUIRE;
                break;
                }
            default:
              JOptionPane.showMessageDialog(frame, "Invalid choice tag in " +
                 "Subject Public Key OID"); 
              return false;       
              }
            }
          }
        }
      }
     
    //System.out.println("n is " + n + "num is " + np.getNumNames());
    for (i = 0; i < n; i++) 
      {
      np.setChoice(i, res[i]); 
      //System.out.println(i + " " + res[i]);
      }
    if (ind != -1) 
      {
      disableOtherAlgo(np, ind);
      }

    // get key size
    Member m2 = m.rule.ref.definerSeq.members.member.index(1);
    if (m2 != null && m2.rule != null && m2.rule.ref != null &&
      m2.rule.ref.wrapper != null && m2.rule.ref.wrapper.rule != null &&
      m2.rule.ref.wrapper.rule.ref != null &&
      m2.rule.ref.wrapper.rule.ref.definedBy != null &&
      m2.rule.ref.wrapper.rule.ref.definedBy.member != null)
      {
      Member m21 = m2.rule.ref.wrapper.rule.ref.definedBy.member.index(0);
      if (m21.rule != null && m21.rule.ref != null &&
        m21.rule.ref.sequence != null && m21.rule.ref.sequence.members.numitems() > 0)
        {
        Member m211 = m21.rule.ref.sequence.members.member.index(0);
        if (m211 != null)
          {
          m211.siz.lo.number.read(tagRef);
          loKeySize = (tagRef.val - 1) * 8;
          m211.siz.hi.number.read(tagRef);
          hiKeySize = (tagRef.val - 1) * 8;
          loText.setText(Integer.toString(loKeySize));
          hiText.setText(Integer.toString(hiKeySize));
          }
        }
      }
    return true;
    }  
}

