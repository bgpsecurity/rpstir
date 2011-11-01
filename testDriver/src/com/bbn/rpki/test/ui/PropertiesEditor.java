/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;

import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.text.JTextComponent;

import com.bbn.rpki.test.model.TestModel;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class PropertiesEditor {
  protected final TestModel testModel;
  protected final JFileChooser fileChooser = new JFileChooser(new File("."));
  protected final JPanel taskPanel = new JPanel(new GridBagLayout());
  protected final GridBagConstraints gbc = new GridBagConstraints();
  protected TaskDescriptionsEditor taskDescriptionsEditor;

  /**
   * @param testModel
   * @param taskDescriptionsEditor 
   */
  protected PropertiesEditor(TestModel testModel, TaskDescriptionsEditor taskDescriptionsEditor) {
    this.testModel = testModel;
    this.taskDescriptionsEditor = taskDescriptionsEditor;
  }

  /**
   * @return the UI component
   */
  public Component getComponent() {
    return taskPanel;
  }

  protected void addToTaskPanel(String label, Component... components) {
    addToTaskPanel(new JLabel(label), components);
  }
  
  protected void addToTaskPanel(JLabel label, Component... components) {
    if (gbc.gridy < 0) {
      gbc.gridy = 0;
      gbc.insets = new Insets(5, 5, 5, 5);
    }
    gbc.gridx = 0;
    gbc.gridwidth = 1;
    gbc.anchor = GridBagConstraints.NORTHWEST;
    gbc.weightx = 0;
    gbc.weighty = 0;
    gbc.fill = GridBagConstraints.NONE;
    taskPanel.add(label, gbc);
    for (int i = 0; i < components.length; i++) {
      Component component = components[i];
      if (i == components.length - 1) {
        gbc.gridwidth = 5 - i;
      } else {
        gbc.gridwidth = 1;
      }
      if (component instanceof JScrollPane) {
        gbc.weighty = 1f;
        gbc.fill = GridBagConstraints.BOTH;
      } else {
        gbc.fill = GridBagConstraints.HORIZONTAL;
      }
      gbc.weightx = 1f;
      gbc.gridx++;
      taskPanel.add(component, gbc);
    }
    gbc.gridy++;    
  }


  /**
   * @param textField
   */
  protected void initTextField(JTextComponent textField, String text) {
    if (text == null) {
      textField.setText("");
      textField.setEnabled(false);
    } else {
      textField.setEnabled(true);
      textField.setText(text);
      textField.select(0, text.length());
    }
  }


  /**
   * @param textField
   */
  protected void initBooleanField(JCheckBox textField, Boolean selected) {
    if (selected == null) {
      textField.setSelected(false);
      textField.setEnabled(false);
    } else {
      textField.setEnabled(true);
      textField.setSelected(selected);
    }
  }
}
