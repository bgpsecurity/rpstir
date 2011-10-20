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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class VersionPane extends FieldBasePane
implements RuleListener  {

  private String myType = "CERT"; // Default is CERT
  private String choice1 = RuleEditorData.ALLOW;
  private String choice2 = RuleEditorData.ALLOW;
  private String choice3 = RuleEditorData.ALLOW; 
  private String v1 = "Version one ";
  private String v2 = "Version two ";
  private String v3 = "Version three ";
  private Dimension dim = new Dimension(120, 20);;
  private ThreeWayCombo pane1;
  private ThreeWayCombo pane2;
  private ThreeWayCombo pane3;
  private JFrame frame;
  
  public VersionPane(String type) {
      myType = type;
      if (myType == "EE" || myType == "CA") {
	choice1 = RuleEditorData.PROHIBIT;
	choice2 = RuleEditorData.PROHIBIT;
	choice3 = RuleEditorData.REQUIRE; 
      } else if (myType.equals("CRL")) {
	choice1 = RuleEditorData.PROHIBIT;
	choice2 = RuleEditorData.REQUIRE;
	choice3 = RuleEditorData.PROHIBIT; 
      }
      pane1 = new ThreeWayCombo(v1, choice1);
      pane2 = new ThreeWayCombo(v2, choice2);
      pane3 = new ThreeWayCombo(v3, choice3);

    try {
      initDisplay();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  public void print() {
    pane1.print();
    pane2.print();
    if (myType == "CERT") {
      pane3.print();
    }

  }

  public int createRule(Member m) {
    
    // check at least one value is selected, aka not prohibit
    if (choice1 == RuleEditorData.PROHIBIT && 
	choice2 == RuleEditorData.PROHIBIT && 
	choice3 == RuleEditorData.PROHIBIT) {
      JOptionPane.showMessageDialog(frame,
				    "No version set to Allow or Require.\nPlease click on Version field to select the version"); 

      return RuleEditorData.FAILED;
    }
    
    
    if (choice1 == RuleEditorData.REQUIRE || 
	(choice1 == RuleEditorData.ALLOW && 
	 choice2 != RuleEditorData.ALLOW && 
	 choice3 != RuleEditorData.ALLOW)) {
      // Only version 1 is allowed, No show for version 
      return RuleEditorData.OK;
    }
    
    m.name.write("Version");
    // Explicit version tag ctx(x80)+construct(0x20)
    m.tagtype.write(AsnStatic.ASN_CONT_CONSTR); //0x00A0    
    if (choice1 == RuleEditorData.ALLOW && 
	(choice2 == RuleEditorData.ALLOW ||
	 choice3 == RuleEditorData.ALLOW)) { 
      m.optional.write(AsnStatic.ASN_BOOL_TRUE);
    } 
    // else (choice 1 == prohibit)do nothing 
    
    //RuleChoice rc = new RuleChoice();// CompoundRule 
    //m.rule.add(rc);
    m.rule.add();
    RuleChoice rc = m.rule.ref;
    
    rc.sequence.members.member.index(0).insert();
    Member m1 = (Member)rc.sequence.members.member.index(0);
    m1.name.write("Version Value");
    m1.tagtype.write(AsnStatic.ASN_INTEGER); //0x02
    
    m1.rule.add();
    Rule p = (Rule)m1.rule.ref.primitive;// Rule 
    //p.rule.add(); 
    //p.rule.ref.none.write(""); //no more rule
    if (choice2 == RuleEditorData.REQUIRE) {
      p.targets.require.target.index(0).insert();
      ((Target)p.targets.require.target.index(0)).num.write(1);
    } else if (choice3 == RuleEditorData.REQUIRE) {
      p.targets.require.target.index(0).insert();
      ((Target)p.targets.require.target.index(0)).num.write(2);
    }
    else { // Allow
      int ind = 0;
      if (choice1 == RuleEditorData.ALLOW) {
	//p.targets.allow.target.index(ind).insert();
	// ((Target)p.targets.allow.target.index(ind++)).num.write(0);
      }
      if (choice2 == RuleEditorData.ALLOW) {
	p.targets.allow.target.index(ind).insert();
	((Target)p.targets.allow.target.index(ind++)).num.write(1);
      }
      if (choice3 == RuleEditorData.ALLOW) {
	p.targets.allow.target.index(ind).insert();
	((Target)p.targets.allow.target.index(ind++)).num.write(2);
      }
      
    }
    
    return RuleEditorData.SUCCESS;
    
  }

  public boolean setRule(Member m) {
    AsnIntRef valueRef = new AsnIntRef();
    AsnIntRef tagRef = new AsnIntRef();
    int ni, i;

    if (m != null && m.rule != null && m.rule.ref.sequence != null &&
      m.rule.ref.sequence.members != null)
      {
      Member m1 = m.rule.ref.sequence.members.member.index(0);
      if (m1 != null && m1.rule != null && m1.rule.ref != null &&
        m1.rule.ref.primitive != null)
        {
        Rule p = m1.rule.ref.primitive;
        if (p.targets != null)
          {
          if (m.optional != null) 
            { // optional is true, so version 1 is allowed. 
            setChoice1(RuleEditorData.ALLOW, true);
            }
          p.targets.tag(tagRef);
          i = (tagRef.val & ~(AsnStatic.ASN_CONT_CONSTR));
          switch(i) 
            {
          case RulesStatic.id_forbid:
            ni = p.targets.forbid.numitems();
            for (i = 0; i < ni; i++) 
              {
              p.targets.forbid.target.index(i).num.read(valueRef);
              //System.out.println(" Version num (forbid): " + valueRef.val);		  
              switch(valueRef.val) 
                {
              case 0: setChoice1(RuleEditorData.PROHIBIT, false); break;
              case 1: setChoice2(RuleEditorData.PROHIBIT, false); break;
              case 2: setChoice3(RuleEditorData.PROHIBIT, false); break;
              default:
                JOptionPane.showMessageDialog(frame, "Too many forbid options in Version");
                return false;
                }  // end inner case
              }
            break; // end forbid switch
          case RulesStatic.id_allow:
            ni = p.targets.allow.numitems();
            for (i = 0; i < ni; i++) 
              {
              p.targets.allow.target.index(i).num.read(valueRef);
              //System.out.println(" Version num (allow): " + valueRef.val);		
              switch(valueRef.val) 
                {
              case 0: setChoice1(RuleEditorData.ALLOW, true); break;
              case 1: setChoice2(RuleEditorData.ALLOW, true); break;
              case 2: setChoice3(RuleEditorData.ALLOW, true); break;
              default:
                JOptionPane.showMessageDialog(frame, "Too many allow options in Version");
                return false;
                }
              }  // end for
            break;  // end allow switch
          case RulesStatic.id_require:
            if (p.targets.require.numitems() > 1)
              {
              JOptionPane.showMessageDialog(frame, "Too many require options (" +
                 p.targets.require.numitems() + ") in Version");
              return false;
              } 
            p.targets.require.target.index(0).num.read(valueRef); // only 1
            //System.out.println(" Version num (require): " + valueRef.val);
            switch(valueRef.val) 
              {
            case 0: 
              setChoice1(RuleEditorData.REQUIRE, false);
              setChoice2(RuleEditorData.PROHIBIT, false);
              setChoice3(RuleEditorData.PROHIBIT, false);  
              break;
            case 1: 
              setChoice2(RuleEditorData.REQUIRE, false); 
              setChoice1(RuleEditorData.PROHIBIT, false);
              setChoice3(RuleEditorData.PROHIBIT, false); 
              break;
            case 2: 
              setChoice1(RuleEditorData.PROHIBIT, false);
              setChoice2(RuleEditorData.PROHIBIT, false); 
              setChoice3(RuleEditorData.REQUIRE, false); 
              break;
            default:
              JOptionPane.showMessageDialog(frame, "Too many require choices in Version");
              return false;
              }  // end require switch
            break;
          default:
            JOptionPane.showMessageDialog(frame, "Invalid option (" + i + ") in Rule in Version"); 
            return false;             
            }  // end outer switch
          }  // end if(p.targets...
        }  // end if(m1 != null...
      }  // end if(m != null...
    repaint();
    return true;
  }
  
  public String getChoice1() {
    choice1 = pane1.getChoice();
    return choice1;
  }

  public String getChoice2() {
    choice2 = pane2.getChoice();
    return choice2;
  }

  public String getChoice3() {
    choice3 = pane3.getChoice();
    return choice3;
  }
    
  public void setChoice1(String choice, boolean enable) {
    choice1 = choice;
    pane1.setChoice(choice);
    pane1.setEnabled(enable);
    pane1.resetChoice();
  }

  public void setChoice2(String choice, boolean enable) {
    choice2 = choice;
    pane2.setChoice(choice);
    pane2.setEnabled(enable);
    pane2.resetChoice();
  }

  public void setChoice3(String choice, boolean enable) {
    choice3 = choice;
    pane3.setChoice(choice);
    pane3.setEnabled(enable);
    pane3.resetChoice();
  }
    
  private void initDisplay() {
    // Create a version pane

    JPanel innerPane = new JPanel();
    JLabel label;
    innerPane.add(Box.createRigidArea(new Dimension(0,5)));
    innerPane.setLayout(new BoxLayout(innerPane, BoxLayout.Y_AXIS));
    if ( (choice1 == RuleEditorData.ALLOW) ||
	 (choice1 == RuleEditorData.ALLOW) ||
	 (choice1 == RuleEditorData.ALLOW))
    {
	label = new JLabel
            ("  Please check the version(s) availability: ");

	label.setAlignmentX(Component.CENTER_ALIGNMENT);
	label.setFont(new java.awt.Font("Dialog", Font.BOLD, 12));
	innerPane.add(label);
    }
    /*
    if (myType == "CA" || myType == "EE" || 
	myType == "CRL") {
      innerPane.add(Box.createRigidArea(new Dimension(0,20)));
      //certVersionPane.setBackground(Color.white);
      pane1.setRuleCommand(v1);
      pane1.addRuleListener(this);
      pane1.setAlignmentX(Component.CENTER_ALIGNMENT);
      innerPane.add(pane1);
    }
    */
    if (myType == "CRL") {
      innerPane.add(Box.createRigidArea(new Dimension(0,10)));
      pane2.setRuleCommand(v2);
      pane2.addRuleListener(this);
      pane2.setAlignmentX(Component.CENTER_ALIGNMENT);
      innerPane.add(pane2);
    }

    if (myType == "CA" || myType == "EE") {
      innerPane.add(Box.createRigidArea(new Dimension(0,10)));
      pane3.setRuleCommand(v3);
      pane3.addRuleListener(this);
      innerPane.add(pane3);
      pane3.setAlignmentX(Component.CENTER_ALIGNMENT);
    }

    if (myType == "CA" || myType == "EE") {
      pane3.setEnabled(false);
    } else if (myType == "CRL") {
      pane2.setEnabled(false);
    }
    innerPane.add(Box.createRigidArea(new Dimension(0,10)));
    innerPane.setBorder(BorderFactory.createRaisedBevelBorder());

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    add(Box.createRigidArea(new Dimension(0,5)));
    add(innerPane);
    add(Box.createVerticalGlue());
    setBorder(new TitledBorder(new EtchedBorder(), "  Version Number Rule  "));
  }

  private void disableOtherButtons(ThreeWayCombo p) {
    //System.out.println("in disableOtherButtons");
    if (p != pane1)
      pane1.setEnabled(false);
    if (p != pane2)
      pane2.setEnabled(false);
    if (p != pane3)
      pane3.setEnabled(false);
  }

  private void enableOtherButtons(ThreeWayCombo p) {
    if (p != pane1)
      pane1.setEnabled(true);
    if (p != pane2)
      pane2.setEnabled(true);
    if (p != pane3)
      pane3.setEnabled(true);
  }

  private boolean checkButton(ThreeWayCombo c) {
    boolean b = false;

    String choice = c.getChoice();
    //System.out.println(" in checkButton choice: " + choice);
    if (choice == RuleEditorData.ALLOW) {
      b = true;
      //RuleUtils.errorDialog("\"Require\" can't coexist with other choices. \n Reset to previous value");
      JOptionPane.showMessageDialog(frame,
      "\"Require\" can't coexist with other choices. \n Reset to previous value");
    }
    return b;
  }

  private boolean validateOtherButtons(ThreeWayCombo p) {
    boolean stop = false;
    //System.out.println("in validateOtherButtons");
    //System.out.println(choice1 + " " + choice2 + " " + choice3);
    if (p != pane1 && !stop) {
      stop = checkButton(pane1);
    }    
    if (p != pane2 && !stop) {
      stop = checkButton(pane2);
    }
    if (p != pane3 && !stop) {
      stop = checkButton(pane3);
    }
    //System.out.println("in validateOtherButtons stop: " + stop); 
    if (stop) {
      p.resetChoice();
      return false;
    } else {
      disableOtherButtons(p);
      return true;
    }
  }


  private String validateChoice(ThreeWayCombo p) {
    String choice = p.getChoice();
    //System.out.println("in validateChoice choice: " + choice);
    if (choice == RuleEditorData.REQUIRE) {
      if (!validateOtherButtons(p)) {
	choice = p.getChoice();
      }
    }
    else {
      enableOtherButtons(p);
    }
    return choice;
  }

  public void rulePerformed(RuleEvent e) {
    String command = ((ThreeWayCombo)e.getSource()).getRuleCommand();
    String choice;
    ThreeWayCombo p = pane1;
    //System.out.println(" In rulePerformed() command: " + command);
    if (command == v1) {
      p = pane1;
      //System.out.print(" pane1: " + p);
    }
    else if (command == v2) {
      p = pane2;
      //System.out.print(" pane2: " + p);
    }
    else if (command == v3) {
      p = pane3;
      //System.out.print(" pane3: " + p);
    }

    choice = validateChoice(p);
    //System.out.println(" In rulePerformed() choice: " + choice);

    if (command == v1) {
      choice1 = choice;
      //System.out.println(" In rulePerformed() choice1: " + choice1);
    }
    else if (command == v2){
      choice2 = choice;
      //System.out.println(" In rulePerformed() choice2: " + choice2);
    }
    else if (command == v3) {
      choice3 = choice;
      //System.out.println(" In rulePerformed() choice3: " + choice3);
    }
  }


}
