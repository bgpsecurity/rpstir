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

public class KUPane extends ExtnFieldBasePane 
implements NameListener {

  private String[] myChoice;
  private String[] kuData;
  private int[] kuBits;
  NamePane np;
  //String myType;
  private JFrame frame;

  //public abstract void setData();
  //public abstract String[] getData();
  //public abstract String getName(int i);
  //public abstract int setExtraRule(int tmp);
  //public abstract boolean inList(String name);
  //public abstract void setRequireChoice();

  static String[] wholeKUdata = {
	"Digital Signature:",
	"Non Repudiation:",
	"Key Encipherment:",
	"Data Encipherment:",
	"Key Agreement:",
	"Cert Sign:",
	"CRL Sign:",
	"Encipher Only:",
	"Decipher Only:" 
  };

  static String[] KUEEdata = {
      "Digital Signature:",
      //"Non Repudiation:",
      //"Key Encipherment:",
      //"Data Encipherment:",
      //"Key Agreement:",
      //"Encipher Only:",
      //"Decipher Only:" 
  };

  static int[] KUEEBits = { 0 };

  static String[] KUCAdata = {
      //"Digital Signature:",
      //"Non Repudiation:",
      //"Key Encipherment:",
      //"Data Encipherment:",
      //"Key Agreement:",
    "Cert Sign:",
    "CRL Sign:",
    //"Encipher Only:",
    //"Decipher Only:" 
  };

  static int[] KUCABits = { 5, 6 };
  
  public KUPane(String type) {
    super("Key Usage", RuleEditorData.REQUIRE, type);
  }
  
  public String getChoice(int i) {
    return np.getChoice(i);
  }

  public String getName(int i) {
    return (kuData[i]);
  }

  public void setRequireChoice(){
    setChoice(0, RuleEditorData.REQUIRE);
    disableUnit(0);
    if (myType.equals("CA")) {
      setChoice(1, RuleEditorData.REQUIRE);
      disableUnit(1);
    }
  }

  public void setChoice(int i, String choice) {
    //myChoice[i] = choice;
    np.setChoice(i, choice);
  }

  public void enableUnit(int i) {
    np.enableUnit(i);
  }

  public void disableUnit(int i) {
    np.disableUnit(i);
  }

  public void namePerformed(NameEvent e) {
    NamePane np = (NamePane)e.getSource();
  }

  public void setContentPane() 
    {
    //String[] data = null;
    if (myType.equals(RuleEditorData.EE_TYPE)) 
      { 
      kuData = KUEEdata;
      kuBits = KUEEBits;
      } 
    else // CA or CRL (in ExtnPane, new KUPane is called regardless of type)
      {
      kuData = KUCAdata;
      kuBits = KUCABits;
      }
    if (kuData.length != 0) 
      {
      np = new NamePane(kuData);
      setRequireChoice(); 
      contentPane.add(np);
      }
    }

  public int createRule(Member m) 
    {
    //System.out.println("createRule for KUPane");
    boolean hasRequire = false;
    boolean hasAllow = false;
    boolean hasForbid = false;
    int tmpForbid, tmpRequire, tmp = 0;
    byte[] forbidBit = new  byte[(wholeKUdata.length + 7) / 8];
    byte[] requireBit = new  byte[(wholeKUdata.length + 7) / 8];
    m.name.write(myName);
    m.tagtype.write(AsnStatic.ASN_BITSTRING);   
    String[] choices = new String[kuData.length];

    for (int i = 0; i < kuData.length; i++)  // get the present choices
      { 
      choices[i] = np.getChoice(i);    
      if (choices[i].equals(RuleEditorData.ALLOW)) hasAllow = true;
      else if (choices[i].equals(RuleEditorData.REQUIRE)) hasRequire = true;
      else if (choices[i].equals(RuleEditorData.PROHIBIT)) hasForbid = true;
      }
    if (!hasAllow && !hasRequire) 
      { // no DN attribute allowed, all prohibit
      JOptionPane.showMessageDialog(frame,
        "No entry in " + "\"" + myName + " set to Allow or Require. \nPlease select the extension to fix the problem"); 
      return RuleEditorData.FAILED;
      }
    m.rule.add();
    NamedBits nb = m.rule.ref.namedBits;// SetSeqOfRule
              //
    for (int i = 0; i < forbidBit.length; i++)
      {
      forbidBit[i] = (byte)0xFF;
      requireBit[i] = (byte)0;
      }
    for (int i = 0; i < kuBits.length; i++)
      {  
      int j = kuBits[i], // get the bit position for this item        
          k = (0x80 >> (j & 7)), // get value of bit 
          n = j / 8;  // get index to byte 
      byte b = (byte)k;     // get the byte
      if (!choices[i].equals(RuleEditorData.PROHIBIT))
        forbidBit[n] &= ~b;  // mark the spot
      if (choices[i].equals(RuleEditorData.REQUIRE))
        requireBit[n] |= b;
      }
    AsnByteArray aba = new AsnByteArray(forbidBit, forbidBit.length);
    nb.forbid.bits.write(aba, requireBit.length, 0);
    aba = new AsnByteArray(requireBit, requireBit.length);
    nb.require.bits.write(aba, requireBit.length, 0);
    return RuleEditorData.SUCCESS;
    }


  public boolean setRule(Member m) 
    {
    int num = wholeKUdata.length, // number of bits in wholekuData;
      nbytes = (num + 7) / 8;     // number of bytes in rule

    NamedBits nb = m.rule.ref.namedBits;// SetSeqOfRule
    AsnIntRef shift = new AsnIntRef();
    AsnByteArray forbidBits = new AsnByteArray();
    AsnByteArray requireBits = new AsnByteArray();
    int lth;
    if (nb.forbid.bits.read(forbidBits, shift) != nbytes ||
      nb.require.bits.read(requireBits, shift) != nbytes)
      {
      JOptionPane.showMessageDialog(frame, "Incompatible rule set in " + myName); 
      return false;
      }
    for (int i = 0; i < kuData.length; i++)
      {
      int j = kuBits[i], // get the bit position for this item        
          k = (0x80 >> (j & 7)), // get value of bit 
          n = j / 8;  // get index to byte 
      byte fb = forbidBits.index(n);
      fb &= (byte)k;
      byte rb = requireBits.index(n);
      rb &= (byte)k;
      if (fb == rb || fb != 0 || rb == 0)  // our policy requires the 2 bits
        {
        JOptionPane.showMessageDialog(frame, "Improper bits in " + myName + " rule set"); 
        return false;
        } 

      if (fb != 0) setChoice(i, RuleEditorData.PROHIBIT);
      else if (rb != 0) setChoice(i,  RuleEditorData.REQUIRE);      
      else setChoice(i, RuleEditorData.ALLOW);
      }
    return true;
    }
  
  



}
