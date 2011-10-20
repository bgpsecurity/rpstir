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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class CrlVersionPane extends VersionPane {
  private String v1, v2;
  
  public CrlVersionPane(String type) {
    super(type);
  }
  
  public String getV1() {
    v1 = getChoice1();
    return v1;
  }
  
  
  public String getV2() {
    v2 = getChoice2();
    return v2;
  }
  
  public void print() {
    //System.out.println("\n");;
    //super.print();
  }
  
} // CertVersionPane 
  
