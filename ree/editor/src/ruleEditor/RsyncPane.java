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
import java.util.Enumeration;

public class RsyncPane extends FieldBasePane implements ActionListener, ListSelectionListener
{

    JScrollPane jsp;
    JList rsyncList;
    DefaultListModel rsyncContents;
    JButton addButton, editButton, removeButton;
    JTextField textField;
    JPanel buttonPane, rsyncPanel;
    String myType;
    int done, todo;
    boolean isEnabled;

    RsyncPane(String type)
    {
	setContentPane();
	myType = type;
        done = todo = 0;
	isEnabled = true;
    }

    public int createRule(Member m)
    {
        m.tagtype.write(AsnStatic.ASN_CONT_SPEC + 6);
	m.rule.add();
        Rule ru = (Rule)m.rule.ref.primitive;
        int i = 0, j = 0; 
        for (Enumeration e = rsyncContents.elements();
            j < todo && e.hasMoreElements(); i++)
            {
            String x = (String)e.nextElement();
            if (i < done) continue;
            ru.targets.require.target.index(j).insert();	 
            Target ta = ru.targets.require.target.index(j++);
            ta.value.write(x);
               //  System.out.println(x);
            }  

	return RuleEditorData.SUCCESS;
    }

    public void setList(String[] list)
    {
	rsyncContents.clear();
	for (int i=0; i< list.length; i++)
	    rsyncContents.addElement(list[i]);
    }

    public void setRule(String[] list)
    {
	rsyncContents.clear();
	for (int i=0; i< list.length; i++)
	    rsyncContents.addElement(list[i]);
    }

    public boolean setRule(Member m)
    {
	// currently unused.  
	// issuerDistPointPane, crlDistPointPane, 
	// authInfoAccess, subjInfoAccess all call setRule(String[] list)

	rsyncContents.clear();  // empties the list
        Targets targets = m.rule.ref.primitive.targets.require;
        AsnByteArray locaba = new AsnByteArray();
        m.name.read(locaba);
        // System.out.println("RsyncPane member " + locaba.toString() + " " + targets.numitems());
        for (int i = 0, j = targets.numitems(); i < j; i++)
            {
            Target ta = targets.target.index(i);
            AsnByteArray aba = new AsnByteArray(ta.vsize());
            ta.value.read(aba);
            String val = aba.toString();
	    rsyncContents.addElement(val);
            }
	return true;
    }

    public void setContentPane()
    {
	JPanel labPane = new JPanel();
	labPane.add(new JLabel("List of URI's: (first must be an RSYNC URI)"));
	labPane.add(Box.createRigidArea(new Dimension(240,0)));
	JPanel midPane = new JPanel();
	midPane.setLayout(new BoxLayout(midPane, BoxLayout.Y_AXIS));

	jsp = new JScrollPane();
	rsyncContents = new DefaultListModel();
	rsyncList = new JList();
	rsyncList.addListSelectionListener(this);
	rsyncList.setModel(rsyncContents);
	//rsyncList.setPreferredSize(new Dimension(50,10));
	jsp.setViewportView(rsyncList);
	midPane.add(jsp);
	
	addButton = new JButton("Add");
	editButton = new JButton("Edit");
	removeButton = new JButton("Remove");
	addButton.addActionListener(this);
	editButton.addActionListener(this);
	removeButton.addActionListener(this);
	textField = new JTextField(15);
	//textField.setText("rsync://boston.com");
	buttonPane = new JPanel();
	buttonPane.add(textField);
	buttonPane.add(addButton);
	buttonPane.add(editButton);
	buttonPane.add(removeButton);

	rsyncPanel = new JPanel();
	rsyncPanel.add(Box.createRigidArea(new Dimension(0,20)));
	rsyncPanel.add(labPane);
	rsyncPanel.add(midPane);
	rsyncPanel.add(buttonPane);

	rsyncPanel.setLayout(new BoxLayout(rsyncPanel, BoxLayout.Y_AXIS));
	//add(rsyncPanel);
	add(rsyncPanel);
    }

    public void actionPerformed(ActionEvent e)
    {
	Object obj = e.getSource();
	if (obj == addButton)
	    addPushed();
	else if (obj == editButton)
	    editPushed();
	else if (obj == removeButton)
	    removePushed();
    }

    public void valueChanged(ListSelectionEvent e)
    {
	if (isEnabled == false)
	{
	    rsyncList.clearSelection();
	    return;
	}
	String sel  = (String) rsyncList.getSelectedValue();
	if (sel != null)
	    textField.setText(sel);
    }

    public void addPushed()
    {
	String toAdd = textField.getText().trim();
	if (isRsync(toAdd))
	{
	    if (rsyncContents.size() == 0)
		rsyncContents.addElement(toAdd);
	    else 
	    {
	       //toAdd = "rsync://" + toAdd;
		JOptionPane.showMessageDialog(null,
					  "Only one RSYNC URI allowed.",
					  "Multiple RSYNC URI's",
					  JOptionPane.ERROR_MESSAGE);
		return;
	    }
	}
	else if (rsyncContents.size() == 0)
	{
	    	JOptionPane.showMessageDialog(null,
					  "The first URI must be an RSYNC URI",
					  "Incorrect URI",
					  JOptionPane.ERROR_MESSAGE);
		return;
	}
	else if (!checkURI(toAdd))
	    return;
	else if (toAdd.length() > 1)
	{
	    if (!rsyncContents.contains(toAdd))
		rsyncContents.addElement(toAdd);
	    else
		JOptionPane.showMessageDialog(null,
					  toAdd + " is already in the list.",
					  "List Duplication",
					  JOptionPane.WARNING_MESSAGE);
	}
    }
    
    public void editPushed()
    {
	int i = rsyncList.getSelectedIndex();
	if (i == -1)
	    JOptionPane.showMessageDialog(null,"Nothing selected for editing.",
			     "Empty Selection", JOptionPane.WARNING_MESSAGE);
	else
	{
	    String theValue = textField.getText().trim();
	    if (!checkURI(theValue))
		return;
	    if (i>0)
	    {
		if (!isRsync(theValue))
		    rsyncContents.setElementAt(theValue, i);
		else
		    JOptionPane.showMessageDialog(null,"RSYNC can only be the first" 
						  + " element.",
			     "Multiple RSYNC Error", JOptionPane.WARNING_MESSAGE);
	    }
	    else if (isRsync(theValue))
		rsyncContents.setElementAt(theValue, i);
	    else
		JOptionPane.showMessageDialog(null,
					  "The first URI must be an RSYNC URI",
					  "Incorrect URI",
					  JOptionPane.ERROR_MESSAGE);	
	}

		
    }

    public void removePushed()
    {
	int i = rsyncList.getSelectedIndex();
	if (i == 0)
	    JOptionPane.showMessageDialog(null,
					  "Cannot remove RSYNC URI.",
					  "Invalid Removal",
					  JOptionPane.WARNING_MESSAGE);
	else if (i > 0)
	    rsyncContents.remove(i);
	/*
	else if (rsyncContents.getSize() <= 1)
	{
	    JOptionPane.showMessageDialog(null,
					  "Cannot remove last entry.",
					  "Invalid Command",
					  JOptionPane.WARNING_MESSAGE);
	    rsyncList.clearSelection();
	}
	*/
	else if (i == -1)
	    JOptionPane.showMessageDialog(null,
					  "Nothing selected for removal.",
					  "Empty Selection",
					  JOptionPane.WARNING_MESSAGE);
    }

    public boolean checkURI(String toAdd)
    {
	if (toAdd.indexOf("://") < 3)
	{
	    JOptionPane.showMessageDialog(null,
					  "Malformed URI",
					  "Malformed URI",
					  JOptionPane.ERROR_MESSAGE);
	}
	return true;
    }

    public boolean isRsync(String toAdd)
    {
	if ((toAdd.startsWith("rsync://")) || (toAdd.startsWith("RSYNC://")))
	    return true;
	else return false;
    }

    public void setDisabled()
    {
	rsyncPanel.remove(buttonPane);
	isEnabled = false;
	rsyncList.setToolTipText("List not selectable.  Contents are from CA Certificate.");
    }
    
    public void resetContents()
    {
	rsyncContents.clear();
    }
    
}
