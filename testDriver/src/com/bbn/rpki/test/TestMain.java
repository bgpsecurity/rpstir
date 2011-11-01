/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;

import com.bbn.rpki.test.model.TestModel;
import com.bbn.rpki.test.ui.TaskDescriptionsEditor;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class TestMain {
  /**
   * @param args
   * @throws IOException
   * @throws JDOMException
   */
  public static void main(String...args) throws IOException, JDOMException {
    File modelFile = new File("model.xml");
    JFrame frame = new JFrame("Task Description Editor");
    frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
    final TestMain testMain = new TestMain(modelFile);
    frame.getContentPane().add(testMain.getComponent());
    frame.setJMenuBar(testMain.getJMenuBar());
    WindowListener windowListener = new WindowAdapter() {

      /**
       * @see java.awt.event.WindowAdapter#windowClosing(java.awt.event.WindowEvent)
       */
      @Override
      public void windowClosing(WindowEvent e) {
        testMain.exit();
      }
    };
    frame.addWindowListener(windowListener);
    frame.pack();
    frame.setVisible(true);
  }

  private TestModel testModel;
  private final JTabbedPane tabbedPane = new JTabbedPane();
  private final Action saveAction = new AbstractAction("Save") {

    @Override
    public void actionPerformed(ActionEvent e) {
      try {
        save();
      } catch (IOException e1) {
        JOptionPane.showMessageDialog(getComponent(), "Exception saving testModel");
      }
    }
  };
  private final Action exitAction = new AbstractAction("Exit") {

    @Override
    public void actionPerformed(ActionEvent e) {
      exit();
    }
  };
  private final File modelFile;
  
  TestMain(File modelFile) throws IOException, JDOMException {
    this.modelFile = modelFile;
    if (modelFile != null && modelFile.canRead()) {
      FileReader fileReader = new FileReader(modelFile);
      SAXBuilder builder = new SAXBuilder();
      Document doc = builder.build(fileReader);
      Element root = doc.getRootElement();
      testModel = new TestModel(root);
    } else {
      testModel = new TestModel();
    }
    TaskDescriptionsEditor tde = new TaskDescriptionsEditor(testModel);
    tabbedPane.add("Task Descriptions", tde.getComponent());
  }
  
  /**
   * 
   */
  protected void exit() {
    if (testModel.isModified()) {
      String[] msg = {
          "Modifications have been made.",
          "Do you want to save before exiting?"
      };
      int option = JOptionPane.showConfirmDialog(getComponent(), msg, "Unsaved Modifications", JOptionPane.YES_NO_CANCEL_OPTION);
      switch (option) {
      case JOptionPane.NO_OPTION:
        break;
      case JOptionPane.YES_OPTION:
        try {
          save();
        } catch (IOException e) {
          JOptionPane.showMessageDialog(getComponent(), "Exception writing testModel");
          return;
        }
        break;
        default: return;
      }
    }
    System.exit(0);
  }

  /**
   * @throws IOException 
   * 
   */
  protected void save() throws IOException {
    Element rootElement = new Element("test-model");
    testModel.toXML(rootElement);
    FileWriter writer = new FileWriter(modelFile);
    Document doc = new Document(rootElement);
    new XMLOutputter(Format.getPrettyFormat()).output(doc, writer);
  }

  /**
   * @return the UI component
   */
  public Component getComponent() {
    return tabbedPane;
  }
  
  /**
   * @return the menu bar
   */
  public JMenuBar getJMenuBar() {
    final JMenuBar menuBar = new JMenuBar();
    JMenu fileMenu = new JMenu("File");
    fileMenu.add(saveAction);
    fileMenu.addSeparator();
    fileMenu.add(exitAction);
    menuBar.add(fileMenu);
    return menuBar;
  }
}
