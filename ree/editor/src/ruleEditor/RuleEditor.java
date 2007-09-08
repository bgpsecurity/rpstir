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

import ruleEditor.*;

import java.awt.event.*;
import java.awt.*;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JMenuBar;
import javax.swing.JFrame;
import javax.swing.UIManager;
import javax.swing.event.*;
import javax.swing.plaf.FontUIResource;


public class RuleEditor {
  //implements ActionListener {
  boolean packFrame = false;
  RuleEditorData red = new RuleEditorData();

  public RuleEditor() {
    display();
  }

  private void display() {
      RuleUtils.ruleFrame = new JFrame("BBN Rule Editor");

    //Center the window
    Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    Dimension modScreenSize = null;
    if (screenSize.getHeight() > 900) {
      System.out.println(" Use default screen size");
      RuleUtils.ruleFrame.setSize(new Dimension(1020, 900));
    } else {
      int y = screenSize.height; // - 40; // - 40 for mac
      int x = screenSize.width;
      modScreenSize = new Dimension(x, y);
      RuleUtils.ruleFrame.setSize(modScreenSize);
    }
    Dimension frameSize = RuleUtils.ruleFrame.getSize();
    System.out.println("Frame size: " + frameSize + " \nscreenSize: " + screenSize);
    if (frameSize.height > screenSize.height) {
      frameSize.height = screenSize.height; // -40; // -40 for mac
    }
    if (frameSize.width > screenSize.width) {
      frameSize.width = screenSize.width;
    }
    RuleUtils.ruleFrame.setLocation((screenSize.width - frameSize.width) / 2, (screenSize.height - frameSize.height) / 2);

    RulePane rp = new RulePane();
    
    //RuleUtils.ruleFrame.getContentPane().add(new ruleEditor.RulePane());
    //ruleFrame.pack();
    RuleUtils.ruleFrame.getContentPane().add(rp);
    RuleUtils.ruleFrame.setSize(new Dimension(1000, 600));
    RuleUtils.ruleFrame.setVisible(true);
    if (RuleUtils.CAfilename != null)
	rp.openCA(false, false);
    else rp.openCA(true, true);
    RuleUtils.ruleFrame.addWindowListener(new WindowAdapter() {
      public void windowClosing(WindowEvent e) {
	ruleEditor.RuleUtils.closeSK();
        System.exit(0);
      }
    });
  }

  //Main method
  public static void main(String[] args) {
    int fontSize = 11; 

    if (args.length > 0) RuleUtils.CAfilename = args[0];
    Font userEntryFont = new Font("Dialog", Font.PLAIN, fontSize);  //"Helvetica", Font.BOLD, 10
    Font defaultFont = new Font("Dialog", Font.PLAIN, fontSize); 
    Font boldFont = new Font("Dialog", Font.BOLD, fontSize); 


    UIManager.put("CheckBox.font",new FontUIResource(defaultFont)); 
    UIManager.put("RadioButton.font",new FontUIResource(defaultFont)); 
    
    UIManager.put("Text.font", new FontUIResource(userEntryFont)); 
    UIManager.put("Tree.font", new FontUIResource(userEntryFont)); 
    UIManager.put("TextField.font", new FontUIResource(userEntryFont)); 
    UIManager.put("TextArea.font", new FontUIResource(userEntryFont)); 
    UIManager.put("TextPane.font", new FontUIResource(userEntryFont)); 
    UIManager.put("List.font", new FontUIResource(userEntryFont)); 
    UIManager.put("Table.font", new FontUIResource(userEntryFont)); 
    UIManager.put("ComboBox.font", new FontUIResource(userEntryFont)); 
    // Non-user entry widgets 
    UIManager.put("Button.font",new FontUIResource(defaultFont)); 
    UIManager.put("Label.font", new FontUIResource(defaultFont)); 
    UIManager.put("Menu.font", new FontUIResource(defaultFont)); 
    UIManager.put("MenuItem.font", new FontUIResource(defaultFont)); 
    UIManager.put("ToolTip.font", new FontUIResource(defaultFont)); 
    UIManager.put("ToggleButton.font", new FontUIResource(defaultFont)); 
    //UIManager.put("TitledBorder.font", new FontUIResource(boldFont)); 
    UIManager.put("PopupMenu.font", new FontUIResource(defaultFont)); 
    UIManager.put("TableHeader.font", new FontUIResource(defaultFont)); 
    UIManager.put("PasswordField.font", new FontUIResource(defaultFont)); 
    // Containters 
    UIManager.put("ToolBar.font", new FontUIResource(defaultFont)); 
    UIManager.put("MenuBar.font", new FontUIResource(defaultFont)); 
    UIManager.put("Panel.font", new FontUIResource(defaultFont)); 
    UIManager.put("ProgressBar.font", new FontUIResource(defaultFont)); 
    UIManager.put("TextPane.font", new FontUIResource(defaultFont)); 
    UIManager.put("OptionPane.font", new FontUIResource(defaultFont)); 
    UIManager.put("ScrollPane.font", new FontUIResource(defaultFont)); 
    UIManager.put("EditorPane.font", new FontUIResource(defaultFont)); 
    UIManager.put("ColorChooser.font", new FontUIResource(defaultFont)); 
    
    try {
      UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    }
    catch(Exception e) {
      e.printStackTrace();
    }

    new RuleEditor();
  }
}
