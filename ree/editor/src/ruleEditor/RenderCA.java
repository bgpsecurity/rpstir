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
import skaction.*;
import Algorithms.*;
import name.*;
import certificate.*;
import extensions.*;

import java.util.*;
import java.io.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class RenderCA {
  private static JFrame frame;
    //private Component myParent;
  private IssuerName issuerName = new IssuerName();
  private byte[] serialNum;
  private byte[] subjectKeyId; // octet string
  private byte[] CAIssuerName;
  private String[] issuerNameValue;
  private String[] v4List = null;
  private String[] v6List = null;
  private String[] asnList = null;
  private String[] rdiList = null;
  private Vector asn = null; // hold ASPane init data
  private Vector rdi = null; // hold RDIPane init data
  private int n4 = 0, n6 = 0;
  private int as0 = 0, as1 = 0;
  private String[] issuingDistList = new String[0];
  final static JFileChooser fc = new JFileChooser(RuleUtils.RootDir); 
  public Certificate cert;

  public RenderCA()
  {
  }

  public RenderCA(Component parent) {
      //myParent = parent;
   
  }

  public void setSubordinate(int n) {
    issuerName.setSubordinate(n);
  }

  public String getSubordinateName() {
    return issuerName.getSubordinateName();
  }

  public IssuerName getIssuerName() {
    return issuerName;
  }

  public String[] getIssuingDistList()
    {
    return issuingDistList;
    }

  public String[] getIssuerNameStrings() {
    return issuerNameValue;
  }

  public byte[] getSerialNum() {
    return serialNum;
  }

  public byte[] getCAIssuerName() {

    return CAIssuerName;
  }

  public byte[] getSubjectKeyId() {
    return subjectKeyId;
  }

  public String[] getV4List() {
    return v4List;
  }

  public String[] getV6List() {
    return v6List;
  }

  public String[] getAsnList() {
    return asnList;
  }

  public String[] getRdiList() {
    return rdiList;
  }

  public int getAsnListCount() {
    if (asnList != null) {
      return asnList.length;
    } else {
      return 0;
    }
  }

  public int getRdiListCount() {
    if (rdiList != null) {
      return rdiList.length;
    } else {
      return 0;
    }
  }

  public File getCAFile(boolean replace)
  {
      File file;
      int n;
      int returnVal = fc.showDialog(null, "Retrieve CA Certificate File");
       
      if ( returnVal != JFileChooser.APPROVE_OPTION)
      {   
	  if (RuleUtils.CAfilename == null)
	  {
	    int val = JOptionPane.showConfirmDialog(null,
					"Cannot continue without CA " +
                                        "Certificate.  Do you want to quit?",
					"User Cancelled.",
					JOptionPane.YES_NO_OPTION);
	    if (val == JOptionPane.YES_OPTION)
	    {
	      System.out.println("Exiting." );
	      System.exit(0);
	    }
	  }
          else return null;
      }
      File dir = fc.getCurrentDirectory();
      file = fc.getSelectedFile();
      //if (issuerName.getItemNum() != 0) 
      if (replace)
      { // CA exists
        n = JOptionPane.showConfirmDialog(frame, "You are about to replace " +
			"the CA certificate information with this one." +
			"Are you sure you want to do this?");
        if (n == JOptionPane.YES_OPTION) 
        {
	  // continue
          issuerName.delete(); // delete old CA cert
	}  
        else if (n == JOptionPane.NO_OPTION || 
		 n == JOptionPane.CANCEL_OPTION ) 
        {
	    JOptionPane.showMessageDialog(frame, 
               "Retrieving certificate cancelled by the user."); 
	    return null;
	}
      }
      return file;
  }

  public boolean newCA(boolean newFile, boolean replace)
  {
      if (!replace && newFile)
        JOptionPane.showMessageDialog(frame, 
              "Please retrieve a CA's Certificate file", 
              "", JOptionPane.INFORMATION_MESSAGE); 
      if (RuleUtils.cert == null)
	  RuleUtils.cert = new RenderCA();
      while (!RuleUtils.cert.CAcertRendering(newFile)) 
      {
	  RuleUtils.CAfilename = null;
	  int val = JOptionPane.showConfirmDialog(frame, 
			       "Would you like to try again?", 
			       "Error.", JOptionPane.YES_NO_OPTION);
	  if (val == JOptionPane.NO_OPTION)
	      System.exit(0);
      }
      return true;
  }
  public boolean CAcertRendering()
  {
      return CAcertRendering(false);
  }

  public boolean CAcertRendering(boolean newFile)
  {
      return CAcertRendering(newFile, false);
  }

  public boolean CAcertRendering(boolean newFile, boolean replace) {
    int lth;
    AsnByteArray tmp;
    File file = null;
    cert = new Certificate();
    if ((RuleUtils.CAfilename != null) && (newFile == false))
	file = new File(RuleUtils.CAfilename); 
    else file = getCAFile(replace);
    if ((RuleUtils.CAfilename == null) && file == null)
	//System.exit(0);
	return false;
    else if (file != null)
	RuleUtils.CAfilename = file.getAbsolutePath();
    else return false;

    RuleUtils.ruleFrame.setTitle("BBN Rule Editor -- " +
				 file.getAbsolutePath());
	     //String fName = file.getAbsolutePath();
	     //if (RuleUtils.CAfilename == null) 
	     //RuleUtils.CAfilename = fName;
    // fName = fName.replace('\\', '/'); //For mac only
    //System.out.println("Retrieving certificate file: "  +  fName + "." );
    int ansr = cert.get_file(file.getAbsolutePath());
    if (ansr < 0) 
      {
	  //System.out.println("Error at " + cert.error.asn_map_string);
      JOptionPane.showMessageDialog(frame, 
         "Reading certificate file error: " + 
         AsnStatic.getErrorMsg(cert.error.getErrorNo()) +
         " at location " + -ansr, "", JOptionPane.ERROR_MESSAGE);
      RuleUtils.CAfilename = null;
      return false;
      } 
    // get serial number
    lth = cert.toBeSigned.serialNumber.vsize();
    tmp = new AsnByteArray(lth);
    cert.toBeSigned.serialNumber.read(tmp);
    serialNum = tmp.getArray();
    //System.out.println(" serial number: " );
    //tmp.print();
    // get CA issuer name
    lth = cert.toBeSigned.issuer.vsize();
    tmp = new AsnByteArray(lth);
    cert.toBeSigned.issuer.read(tmp);
    CAIssuerName = tmp.getArray();
    //System.out.println(" CA issuer name: ");
    //tmp.print();
    // get Issuer subject name
    RDNSequence rdns = cert.toBeSigned.subject.rDNSequence;
    issuerName = RuleUtils.getIssuerNameFromRDNS(rdns);
    setIssuerTabValues(issuerName);
    Extensions extns = cert.toBeSigned.extensions;
    int ni = extns.numitems();
    // reset IP Address Blocks and AS Numbers in case not present
    v4List = v6List = asnList = null;
    for (int i = 0; i < ni; i++) 
      {
      Extension extn = extns.extension.index(i);
      lth = extn.extnID.vsize();
      AsnByteArray objId = new AsnByteArray(lth);
      extn.extnID.read(objId);
      // get subject key id
      if (objId.toString().trim().equals(ExtensionsStatic.id_subjectKeyIdentifier)) 
        { //subject  key id
        lth = extn.extnValue.subjectKeyIdentifier.vsize();
        tmp = new AsnByteArray(lth);
        extn.extnValue.subjectKeyIdentifier.read(tmp);
        subjectKeyId = tmp.getArray();
        //System.out.println(" subject key id : ");
        //tmp.print();
        } 
      else if (objId.toString().trim().equals(ExtensionsStatic.
        id_cRLDistributionPoints ))
        {
        GeneralNames gns = extn.extnValue.cRLDistributionPoints.
          distributionPoint.index(0).distributionPoint.fullName;
        int num = gns.numitems();
        issuingDistList = new String[num];
        for (int ii = 0; ii < num; ii++)
          {
          GeneralName gname = gns.generalName.index(ii);
          AsnByteArray val = new AsnByteArray(gname.vsize());
          gname.read(val);
          issuingDistList[ii] = val.toString();
          }
        }
      else if (objId.toString().trim().equals(ExtensionsStatic.id_pe_ipAddrBlocks)) 
        { // IPAPane
        IPAddrBlocks ipab = extn.extnValue.ipAddressBlock;

        n4 = n6 = 0;
        Vector ipa = getIPAdata(ipab);
        v4List = getV4data(ipa);
        v6List = getV6data(ipa);
        } 
      else if (objId.toString().trim().equals(ExtensionsStatic.id_pe_autonomousSysIds)) 
        { //ASPane
        ASNum asn = extn.extnValue.autonomousSysNum;
        getASdata(asn);
        } 
      }
    return true;
    }

  private void setIssuerTabValues(IssuerName name) {
    int n = name.getItemNum();
    issuerNameValue = new String[n];
    for (int i = 0; i < n; i++) {
      issuerNameValue[i] = new String(name.getDNname(i) + "\t" 
        			      + name.getDNvalue(i) );
      //System.out.println(i + ": " + issuerNameValue[i]);
    }
  }

  private Vector getIPAdata(IPAddrBlocks ipab) {
    Vector data = new Vector();
    int type = 0, safi = 0;
    String str = null;
    int ni = ipab.numitems();
    for (int i = 0; i < ni; i++) {
      AsnByteArray af = new AsnByteArray(10);
      ipab.iPAddressFamily.index(i).addressFamily.read(af);
      byte[] b = af.getArray();
      type = b[1];
      safi = b[2];
      //System.out.println(" type: " + type + " safi: " + safi);
      IPAddressChoice ipac = ipab.iPAddressFamily.index(i).ipAddressChoice;
      AsnIntRef tagRef = new AsnIntRef();
      ipac.tag(tagRef);
      if (tagRef.val != AsnStatic.ASN_SEQUENCE) {
        // error
        System.out.println("IPAddressChoice has wrong data. SequenceOf is expected.");
      } else { // get addresses
        int n = ipac.addressesOrRanges.numitems();
        for (int j = 0; j < n; j++) {
          IPAddressOrRange por = ipac.addressesOrRanges.iPAddressOrRange.index(j);
          AsnIntRef tag = new AsnIntRef();
          por.tag(tag);
          if (tag.val == AsnStatic.ASN_BITSTRING) { // addressPrefix
            AsnByteArray aba = new AsnByteArray();
            por.addressPrefix.encode(aba);
            str = RuleUtils.formAddressString(safi, aba, aba, RuleEditorData.PROHIBIT_NUM, type); 
            data.addElement(str);
            switch (type) {
            case RuleEditorData.IPV4: n4++; break;
            case RuleEditorData.IPV6: n6++; break;
            default:
              JOptionPane.showMessageDialog(frame, "Invalid choice in RenderCA rule set"); 
            }	  
          } else { // addressRange
            AsnByteArray lo = new AsnByteArray();
            AsnByteArray hi = new AsnByteArray();
            por.addressRange.min.encode(lo);
            por.addressRange.max.encode(hi);
            str = RuleUtils.formAddressString(safi, lo, hi, RuleEditorData.PROHIBIT_NUM, type); 
            data.addElement(str);
            switch (type) {
            case RuleEditorData.IPV4: n4++; break;
            case RuleEditorData.IPV6: n6++; break;
            default:
              JOptionPane.showMessageDialog(frame, "Invalid choice in RenderCA rule set"); 
            }	  
          }
        }
      }
    } 

    return data;
    
  }

  private String[] getV4data(Vector data) {
    String[] v4 = new String[n4];

    for (int i = 0; i< n4; i++) {
      v4[i] = (String)data.elementAt(i);
      //System.out.println(" v4: " + v4[i]);
    }
    return v4;
  }

  private String[] getV6data(Vector data) {
    String[] v6 = new String[n6];

    for (int i = n4; i < (n4 + n6); i++) {
      v6[i-n4] = (String)data.elementAt(i);
      //System.out.println(" v6: " + v6[i-n4]);
    }
    return v6;
  }

  private String[] getASsubdata(ASIdentifierChoice item, int type) 
    {
    Vector data = new Vector();
    AsnIntRef tagRef = new AsnIntRef();
    String s = new String();
    int i, n = 0;
    String[] str = null;
   
    item.tag(tagRef);
    switch(tagRef.val) 
      {
    case AsnStatic.ASN_BOOLEAN:
      s = new String("INHERIT");
      n++;
      data.addElement(s);
      break;
    case AsnStatic.ASN_SEQUENCE:
      int ni = item.asNumbersOrRanges.numitems();
      for (i = 0; i < ni; i++) 
        {
        ASNumberOrRange asnr = item.asNumbersOrRanges.aSNumberOrRange.index(i);
        asnr.tag(tagRef);
        switch(tagRef.val) 
          {
        case AsnStatic.ASN_INTEGER:
          AsnIntRef asn = new AsnIntRef();
          asnr.num.read(asn);
          s = new String(Integer.toString(asn.val));
          break;
        case AsnStatic.ASN_SEQUENCE:
          AsnIntRef lo = new AsnIntRef();
          AsnIntRef hi = new AsnIntRef();
          asnr.range.min.read(lo);
          asnr.range.max.read(hi);
          s = new String(Integer.toString(lo.val) + " - " + Integer.toString(hi.val));
          break;
        default:
          JOptionPane.showMessageDialog(frame, "Invalid choice in RenderCA.getASsubdata rule set"); 
          }
        n++;
        data.addElement(s);
        }
      break;
    default:
     JOptionPane.showMessageDialog(frame, "Invalid choice in RenderCA.getASsubdata rule set"); 
    }

    if (n > 0) {
      str = new String[n];
      for (i = 0; i < n; i++) {
        str[i] = (String)data.elementAt(i);
        //System.out.println(str[i]);
      }
    } 
    return str;

  }
  
  private void getASdata(ASNum asn) {
    Vector data = new Vector();
    int type = -1;

    ASIdentifierChoice asnum = asn.asnum;
    ASIdentifierChoice rdi = asn.rdi;

    //System.out.println(" Asn ");
    asnList = getASsubdata(asnum, 0);
    //System.out.println(" Rdi ");
    //rdiList = getASsubdata(rdi, 1);

  }

}
