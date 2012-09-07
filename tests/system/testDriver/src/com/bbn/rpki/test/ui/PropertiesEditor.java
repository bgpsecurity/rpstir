/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.text.JTextComponent;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class PropertiesEditor {
  /**
   * 
   */
  private static final int NCOLS = 5;
  protected final JFileChooser fileChooser = new JFileChooser(new File("."));
  protected final JPanel panel = new JPanel(new GridBagLayout());
  protected final GridBagConstraints gbc = new GridBagConstraints();

  /**
   * @param testModel
   * @param taskDescriptionsEditor 
   */
  protected PropertiesEditor() {
    panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    gbc.gridy = 0;
    gbc.insets = new Insets(1, 1, 1, 1);
  }

  /**
   * @return the UI component
   */
  public Component getComponent() {
    return panel;
  }

  protected void addToTaskPanel(String label, Component... components) {
    addToTaskPanel(new JLabel(label), components);
  }
  
  protected void addComponentsToTaskPanel(Component... components) {
    gbc.gridx = 0;
    gbc.weighty = 0f;
    for (int i = 0; i < components.length; i++) {
      if (i == components.length - 1)
        gbc.gridwidth = NCOLS - i;
      else
        gbc.gridwidth = 1;
      Component component = components[i];
      if (component instanceof JButton || component instanceof JLabel) {
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0f;
        gbc.anchor = GridBagConstraints.CENTER;
      } else {
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1f;
        gbc.anchor = GridBagConstraints.WEST;
      }
      panel.add(component, gbc);
      gbc.gridx++;
    }
    gbc.gridy++;
  }
  
  protected void addToTaskPanel(JLabel label, Component... components) {
    gbc.gridx = 0;
    gbc.gridwidth = 1;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.weightx = 0;
    gbc.weighty = 0;
    gbc.fill = GridBagConstraints.NONE;
    panel.add(label, gbc);
    for (int i = 0; i < components.length; i++) {
      Component component = components[i];
      if (i == components.length - 1) {
        gbc.gridwidth = NCOLS - i - 1;
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
      panel.add(component, gbc);
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
