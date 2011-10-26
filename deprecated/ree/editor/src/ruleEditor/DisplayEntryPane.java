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

abstract class DisplayEntryPane extends JPanel 
implements ListSelectionListener, ActionListener {

  public String myTitle;
  private String myInputTitle;
  private String[] myName;
  private int myVisibleCount;
  private Dimension myScrollPaneDim;
  protected JList list;
  private String[] myOlist;
  protected DefaultListModel listModel;
  public  String addString;
  private JPanel inputButtonPane;
  JScrollPane listScrollPane;
  //JLabel label;
  //private JTextField treeName;
  private Dimension dim;
  
  public DisplayEntryPane(String title) {
    this(title, null, null, 0, null);
  }

  public DisplayEntryPane(String title, String[] name) {
    this(title, null, name, 0, null);
  }

  public DisplayEntryPane(String title, String inputTitle) {
    this(title, inputTitle, null, 0, null);
  }

  public DisplayEntryPane(String title, 
			  String inputTitle, 
			  int visibleCount, 
			  Dimension scrollPaneDim) {
    this(title, inputTitle, null, visibleCount, scrollPaneDim);
  }

  public DisplayEntryPane(String title, 
			  String inputTitle, 
			  String[] name, 
			  int visibleCount,
			  Dimension scrollPaneDim) {
    myTitle = title;
    myInputTitle = inputTitle;
    myOlist = null;
    myName = name;
    myVisibleCount = visibleCount;
    myScrollPaneDim = scrollPaneDim;
    initDisplay();
  }

  public abstract void setInputPanePartialEnabled(boolean b);
  public abstract void setInputPaneEnabled(boolean b);
  public abstract void setInputPane(JPanel inputPane, String inputTitle, String[] name); 
  public abstract String getInputValue(ActionEvent e, String command);
  public abstract void setInputValue(String name, String command);
  public abstract void enableRemoveButton(boolean b);
  public abstract int getInputIndex(String text);

  public void clearList() {
      listModel.clear();
  }
  
  public void setList(String[] itemList) {
    myOlist = itemList;
    listModel.ensureCapacity(myOlist.length);
    for (int i = 0; i < myOlist.length; i++) {
      listModel.addElement(myOlist[i]);
    }
    list.setSelectedIndex(myOlist.length-1);
    if (itemList.length != 0) {
      enableRemoveButton(true);
      setInputPaneEnabled(true);
    }
  }

  public String[] getList() {
    String[] newList = new String[listModel.getSize()];
    for (int i = 0; i < listModel.getSize(); i++) {
      newList[i] = listModel.getElementAt(i).toString();
    }
    return newList;
  }  
  
  public void setPartialEnabled(boolean b) {
    listScrollPane.setEnabled(b);
    setInputPanePartialEnabled(b);
  }   

  public void setEnabled(boolean b) {
    listScrollPane.setEnabled(b);
    setInputPaneEnabled(b);
  }   
  
  private void initDisplay() {
    int count;

    listModel = new DefaultListModel();
    //Create the list and put it in a scroll pane
    list = new JList(listModel);
    if (myOlist != null) {
      for (int i = 0; i < myOlist.length; i++) {
	listModel.addElement(myOlist[i]);
      }
    }
    if (myVisibleCount == 0) {
	count = 5;
    } else {
	count = myVisibleCount;
    }
    list.setVisibleRowCount(count);
    //list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
    list.addListSelectionListener(this);
    listScrollPane = new JScrollPane(list,
				     JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				     JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
    if (myScrollPaneDim == null) {
	dim = new Dimension(100, 100);
    } else {
	dim = myScrollPaneDim;
    }
    //listScrollPane.setMinimumSize(dim);
    //listScrollPane.setPreferredSize(dim);
    //listScrollPane.setMinimumSize(dim);

    // setup inputPane
    inputButtonPane = new JPanel();
    setInputPane(inputButtonPane, myInputTitle, myName);
    inputButtonPane.setBorder(BorderFactory.createLoweredBevelBorder());

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    add(listScrollPane);
    //add(Box.createRigidArea(new Dimension(0,5)));
    add(inputButtonPane); 
    
    setBorder(new TitledBorder(new EtchedBorder(), "  " + myTitle + "  "));
    
  }
  
  private void removeListener(ActionEvent e) {
    //This method can be called only if
    //there's a valid selection
    //so go ahead and remove whatever's selected.
    //int index = list.getSelectedIndex();

    int ind[] = list.getSelectedIndices();
    for (int i = (ind.length - 1); i >= 0; i--){
      listModel.remove(ind[i]);
    }

    int index = ind[0];
    
    int size = listModel.getSize();
    //System.out.println(" index in removeListener(): " + index + " size: " + size);
    
    if (size == 0) {
      //Nobody's left, disable firing.
      enableRemoveButton(false);
      
    } else {
      //Adjust the selection.
      if (index == listModel.getSize())//removed item in last position
	index--;
      list.setSelectedIndex(index);   //otherwise select same index
    }
  }
  
  //This listener is shared by the text field and the hire button
  private void addListener (ActionEvent e, String command) {
    String text = getInputValue(e, command);
    
    //System.out.println(" getInputValue: " + text);
    //User didn't type in a name...
    if (text/*treeName.getText()*/.equals("")) {
      //Toolkit.getDefaultToolkit().beep();
      return;
    }
    
    int index = list.getSelectedIndex();
    int size = listModel.getSize();
    //System.out.println(" index in addListener(): " + index + " size: " + size + " command: " + command);
    
    //If no selection or if item in last position is selected,
    //add the new hire to end of list, and select new hire.
    /*if (index == -1 || (index+1 == size)) {
      if (command.equals("Edit")) { // In edit mode, remove it then add the new
	listModel.remove(index);
	index--;
      }
      listModel.addElement(text);
      //listModel.insertElementAt(treeName.getText(), size);
      list.setSelectedIndex(size);
      
      //Otherwise insert the new hire after the current selection,
      //and select new hire.
      } else {*/
      if (command.equals("Edit")) { // In edit mode, remove it then add the new
	System.out.println(" in addListener. \"edit\" command, about to remove entry"); 
	listModel.remove(index);
	index--;
	//list.setSelectedIndex(index+1);
      } else {
	int ind = getInputIndex(text);
	/*if (ind+1 == size) { // end of list
	  System.out.println(" in addListener. in end of list");
	  listModel.addElement(text);
	  } else {*/
	  listModel.insertElementAt(text, ind);
	  //}
	list.setSelectedIndex(ind);
      }
      //}
  }

  //This listener is for adding prefix to each input string
  private void prefixListener (ActionEvent e, String command) {
    String text = getInputValue(e, command);

    //setInputValue(text, "Add"); Prefix button shoudl be disabled
    /*
    //System.out.println(" getInputValue: " + text);
    //User didn't type in a name...
    if (text/*treeName.getText()/.equals("")) {
      //Toolkit.getDefaultToolkit().beep();
      return;
    }
    
    int index = list.getSelectedIndex();
    int size = listModel.getSize();
    //System.out.println(" index in addListener(): " + index + " size: " + size);
    
    //If no selection or if item in last position is selected,
    //add the new hire to end of list, and select new hire.
    if (index == -1 || (index+1 == size)) {
      if (command == "Edit") { // In edit mode, remove it then add the new
	listModel.remove(index);
	index--;
      }
      listModel.addElement(text /*treeName.getText()/);
      //listModel.insertElementAt(treeName.getText(), size);
      list.setSelectedIndex(size);
      
      //Otherwise insert the new hire after the current selection,
      //and select new hire.
    } else {
      if (command == "Edit") { // In edit mode, remove it then add the new
	listModel.remove(index);
	index--;
      }
      listModel.insertElementAt(text,/*treeName.getText()/ index+1);
      list.setSelectedIndex(index+1);
      } */
  }

  public void actionPerformed(java.awt.event.ActionEvent e) {
    String command = e.getActionCommand();
    //String command = e.getText(); // this works on JButton only, not in JTextField
    //System.out.println("DisplayEntryPane command: " + command + ".");
    if (command.equals("Add") || command.equals("Edit")) {
      addListener(e, command);
    } else if (command.equals("Remove")) {
      removeListener(e);
    }// else { // prefix
    //  prefixListener(e, command);
    //}

  }

  public void valueChanged(ListSelectionEvent e) { //ListSelectionListener
    int size = listModel.getSize();
    int index = list.getSelectedIndex();
    if (e.getValueIsAdjusting() == false) {
      
      if (list.getSelectedIndex() == -1) {
	//No selection, disable remove button.
	enableRemoveButton(false);
	setInputValue("", "Add");
      } else if (index == size) {
      } else {
	//Selection, update text field.
	enableRemoveButton(true);
	String name = list.getSelectedValue().toString();
	setInputValue(name, "Add");
      }
    }
  }
  
}

