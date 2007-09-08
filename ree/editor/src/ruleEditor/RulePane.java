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
import rules.*;
import asn.*;
import skaction.*;
import ruleEditor.*;
import name.*;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class RulePane extends JPanel implements ActionListener {

    public EECertPane eeCertPane = new EECertPane();
    public CrossCertPane crossCertPane = new CrossCertPane();
    public CrlPane crlPane = new CrlPane();
    //public static RenderCA cert = null;
    public EmptyPane emptyPane = new EmptyPane();
    JTabbedPane tabbedPane;
    JDialog dialog;

  public RulePane() {
    try {
      initDisplay();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Do the one-time initializations, including component creation.  
   */
  private void initDisplay() {
    if (!RuleUtils.connectSK())
      System.exit(1);

    //setLayout(new BorderLayout());
    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    tabbedPane = new JTabbedPane(SwingConstants.TOP);

    // Add tabs
    //JLabel statusBar = new JLabel(" ");
    for (int i = 0; i < RuleEditorData.RuleData.length; i++) {
      JPanel pane = null;
      switch(i) {
        case RuleEditorData.EE_CERT_ID: pane = eeCertPane; break;
        case RuleEditorData.CROSS_CERT_ID: pane = crossCertPane; break;
        case RuleEditorData.CRL_ID: pane = crlPane; break;
        default:
         // JOptionPane.showMessageDialog(frame, "Improper bits in RulePane.initDisplay");
         return; 
      };
      
    tabbedPane.addTab(RuleEditorData.RuleData[i],
		      null,
		      pane,
		      "Select to construct " + RuleEditorData.RuleData[i] +" rule");

    }

    tabbedPane.setSelectedIndex(0);

    JButton rcButton = new JButton(" Retrieve CA's Certificate File ");
    rcButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //rcButton.setPreferredSize(new Dimension(100, 30));
    rcButton.setActionCommand("rc");
    rcButton.addActionListener(this);
    //rcButton.setBorder(BorderFactory.createRaisedBevelBorder());
    JButton rrButton = new JButton(" Retrieve Rule File ");
    rrButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //rrButton.setPreferredSize(new Dimension(100, 30));
    rrButton.setActionCommand("rr");
    rrButton.addActionListener(this);
    //rrButton.setBorder(BorderFactory.createRaisedBevelBorder());
    JButton crButton = new JButton(" Create Rule and Save to File ");
    crButton.setFont(new java.awt.Font("Dialog", 1, 13));
    //crButton.setPreferredSize(new Dimension(100, 30));
    crButton.setActionCommand("cr");
    crButton.addActionListener(this);
    //crButton.setBorder(BorderFactory.createRaisedBevelBorder());

    JPanel buttonPane = new JPanel();
    buttonPane.setLayout(new BoxLayout(buttonPane, BoxLayout.X_AXIS));
    buttonPane.add(rcButton);
    buttonPane.add(rrButton);
    buttonPane.add(crButton);
    add(tabbedPane);
    add(buttonPane);
       
    //add(tabbedPane, BorderLayout.NORTH);
    //add(buttonPane, BorderLayout.SOUTH);
    
  }
  
  

  public class AttributePane extends JPanel {

    public AttributePane() {
      JPanel innerPane = RuleUtils.getInnerPane("This rule is for future enhancement.");
      add(innerPane);
    }
  }

  public class TimestampPane extends JPanel {
    public TimestampPane() {
      JPanel innerPane = RuleUtils.getInnerPane("This rule is for future enhancement.");
      add(innerPane);
    }
  }

  public class EmptyPane extends JPanel {

  }
  
    public boolean openCA(boolean newFile, boolean replace)
    {
	CommandPane tab = null;
	String cafile = null;
	boolean pass;
	pass = RuleUtils.cert.newCA(newFile, replace);
	for (int i =0; i< tabbedPane.getTabCount(); i++)
	{
	    tab = (CommandPane) tabbedPane.getComponentAt(i);
	    tab.updateCAInfo();
	    //tab.redraw();
	}
	return pass;
    } 

   /**
   * Handle events from create rule button
   */
  public void actionPerformed(ActionEvent e) 
    {
    String command = e.getActionCommand();
    int returnVal;
    File file = null;
    String fileName = new String("");
    String perFileName = new String();
    //SKAction skaction = new SKAction();
    //RuleChoice rc = new RuleChoice();

    String RootDir = "../certs";
    JFileChooser fc = new JFileChooser(RootDir); 
    CommandPane tab = (CommandPane) tabbedPane.getSelectedComponent();

    if (command == "cr") 
      {     
	  // call createRule with no filename so that user is asked
	  // for filename only if rule is ok.
	int status = tab.createRule(null);
      } 
    else if (command == "rc") 
      {   // retrieve certificate file for issuer name, popup window
	  openCA(true, true);
      } 
    else if (command == "rr") 
      { // retrieve rule file 
      returnVal = fc.showDialog(this, "Retrieve Rule File");
      AsnByteArray buf = new AsnByteArray(5000);
      
      if (returnVal == JFileChooser.APPROVE_OPTION) 
        {
        file = fc.getSelectedFile();
        fileName = file.getAbsolutePath();
        int ansr = tab.skaction.get_file(fileName);
        System.out.println("Retrieving rule file(" + tab.type + "): " + 
			   fileName + " status: " + ansr );
        if (ansr < 0) 
          {
          JOptionPane.showMessageDialog(null, 
       		"Reading rule file error: " + AsnStatic.getErrorMsg(-ansr), 
        	"Error reading file", JOptionPane.ERROR_MESSAGE); 
          return;
          } 
        tab.skaction.req.cmd.sign.signd.rules.toBeSigned.encode(buf);
        RulePackage rp = new RulePackage();
        rp.decode(buf);
        rp.ruleSets.ruleSet.index(0).ruleGroup.fileData.index(0).contents.
            encode(buf);
        // Check issuer name
        RDNSequence rdns = rp.ca.rDNSequence;
        IssuerName ruleIsName = RuleUtils.getIssuerNameFromRDNS(rdns);
        if (!RuleUtils.cert.getIssuerName().equals(ruleIsName)) 
          { 
                JOptionPane.showMessageDialog(null, 
       		"Reading rule file error: Issuer in Rule file does not " +
			    "match opened CA certificate."); 
                return;
          }
        // Check certificate type
        int ruleType = RuleUtils.getRuleType(tab.type);
        AsnIntRef ruleValue = new AsnIntRef();
        rp.ruleSets.ruleSet.index(0).type.read(ruleValue);
        if (ruleType != ruleValue.val) 
          {
	      // If its a different type, change the selected tab
	      String newType = RuleUtils.getTabType(ruleValue.val);
	      int newTab = 0; // default to RuleEditorData.EE_TYPE
	      if (newType == RuleEditorData.CA_TYPE)
		  newTab = 1;
	      else if (newType == RuleEditorData.CRL_TYPE)
		  newTab = 2;
	      tabbedPane.setSelectedIndex(newTab);
	      tab = (CommandPane) tabbedPane.getSelectedComponent();
          }
        tab.rc.decode(buf);
        boolean retVal = tab.setRule(tab.rc);
	if (retVal == false)
	    {
		JOptionPane.showMessageDialog(null, 
       		"Error(s) in rule file.\nResetting to original CA certificate" 
					      +  " contents.",
		 "Error(s) in rule file.", JOptionPane.ERROR_MESSAGE); 
		openCA(false, false);
	    }
        } 
      else // User hit cancel instead of open
        {
        System.out.println("Open command canceled by user." );
        } 
      }
    }
}

