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

public class IssuerName {
  int numItems;
  int subordinates;
  String[] DNname;
  String[] DNvalue;
  String subordintesName;

  public IssuerName() {
    numItems = 0;
  }

  public void delete() {
    for (int i = 0; i < numItems; i++) {
      DNname[i] = null;
      DNvalue[i] = null;    
    } 
    DNname = null;
    DNvalue = null;    
    numItems = 0;
  }

  public IssuerName(int n) {
    setItemNum(n);
  }

  public void setItemNum(int n) { 
    numItems = n;
    DNname = new String[n];
    DNvalue = new String[n];
  }

  public void setItem(int index, String name, String value) {
    DNname[index] = name;
    DNvalue[index] = value;    
  }

  public int getItemNum() {
    return numItems;
  }

  public String getUfn() {
    String name = new String();
    for (int i = (numItems-1); i >= 0; i--) {
      //System.out.println(" Attr name: " + DNname[i] + " " + DNvalue[i]);
      if (i == 0) {
	name = name + RuleUtils.getDNufn(DNname[i]) + "=" + DNvalue[i];
      } else {
	name = name + RuleUtils.getDNufn(DNname[i]) + "=" + DNvalue[i] + ", ";
      }
    }
    //System.out.println(" ufn: " + name);
    return name;
  }

  public String getDNname(int index) {
    return(DNname[index]);
  }

  public String getDNvalue(int index) {
    return(DNvalue[index].trim());
  }

  public boolean equals(IssuerName isName) {
    if (this.numItems == isName.numItems) {
      for (int i = 0; i < numItems; i++) {
	if (DNname[i].equals(isName.DNname[i]) && 
	    DNvalue[i].equals(isName.DNvalue[i])) {
	  // do nothing
	} else {
	  return false;
	}
      }
    } else {
      return false;
    }

    return true;
  }

  public void setSubordinate(int n) {
    subordinates = n;
  }

  public String getSubordinateName() {
    String name = new String();

    for (int i = subordinates; i >= 0; i--) {
      String tmp = RuleUtils.getDNufn(DNname[i]);
      if (i != 0) {
	name = name + tmp + "=" + DNvalue[i].trim() + ",";
      } else {
	name = name + tmp + "=" + DNvalue[i].trim();
      }
    }

    return name;
  }

}
