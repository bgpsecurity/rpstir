/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test;

import java.awt.Component;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;

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
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    TestMain testMain = new TestMain(modelFile);
    frame.getContentPane().add(testMain.getComponent());
    frame.pack();
    frame.setVisible(true);
  }

  private TestModel testModel;
  private final JTabbedPane tabbedPane = new JTabbedPane();
  
  TestMain(File modelFile) throws IOException, JDOMException {
    if (modelFile!= null) {
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
   * @return the UI component
   */
  public Component getComponent() {
    return tabbedPane;
  }
}
