/*
 * Created on Nov 1, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;

import com.bbn.rpki.test.model.ArgDescription;
import com.bbn.rpki.test.model.TaskDescription;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class ArgDescriptionsEditor extends PropertiesEditor {
  private enum AS {
    BLANK, EDIT, NEW
  }
  
  static class ArgComponents {
    private final JTextField argName = new JTextField(20);
    private final JTextField argFormat = new JTextField(20);
    private final JCheckBox isParameter = new JCheckBox();
    private final JTextField argValue = new JTextField(20);
    private final JButton editButton;
    private ArgDescription argDescription;

    ArgComponents(ActionListener editAction) {
      argName.setToolTipText("Enter the name by which this argument will be referenced");
      argFormat.setToolTipText("Enter the command line format for this argument (e.g. subjkeyfile=%s)");
      isParameter.setToolTipText("Select if this argument should always have the specified value");
      editButton = new JButton("Add");
      editButton.addActionListener(editAction);
      argName.addFocusListener(new FocusAdapter() {

        /**
         * @see java.awt.event.FocusAdapter#focusLost(java.awt.event.FocusEvent)
         */
        @Override
        public void focusLost(FocusEvent e) {
          argDescription.setArgName(argName.getText());
        }});
      argFormat.addFocusListener(new FocusAdapter() {

        /**
         * @see java.awt.event.FocusAdapter#focusLost(java.awt.event.FocusEvent)
         */
        @Override
        public void focusLost(FocusEvent e) {
          argDescription.setArgFormat(argFormat.getText());
        }});
      argValue.addFocusListener(new FocusAdapter() {

        /**
         * @see java.awt.event.FocusAdapter#focusLost(java.awt.event.FocusEvent)
         */
        @Override
        public void focusLost(FocusEvent e) {
          argDescription.setArgValue(argValue.getText());
        }});
      isParameter.addActionListener(new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          argDescription.setParameter(isParameter.isSelected());
          updateToolTips();
        }
      });
    }

    void setVisible(AS s) {
      argName.setEnabled(s == AS.EDIT);
      argFormat.setEnabled(s == AS.EDIT);
      isParameter.setEnabled(s == AS.EDIT);
      argValue.setEnabled(s == AS.EDIT);
      editButton.setVisible(s != AS.BLANK);
      switch (s) {
      case EDIT:
        editButton.setText("Remove");
        editButton.setToolTipText("Click to remove this argument");
        break;
      case NEW:
        editButton.setText("Add");
        editButton.setToolTipText("Click to add another argument");
        break;
      case BLANK:
        editButton.setText("");
        break;
      }
    }

    /**
     * @param argDescription
     */
    public void setValues(ArgDescription argDescription) {
      this.argDescription = argDescription;
      if (argDescription != null) {
        argName.setText(argDescription.getArgName());
        argValue.setText(argDescription.getArgValue());
        argFormat.setText(argDescription.getArgFormat());
        boolean parameter = argDescription.isParameter();
        isParameter.setSelected(parameter);
        updateToolTips();
      } else {
        argName.setText("");
        argValue.setText("");
        argFormat.setText("");
      }
    }

    /**
     * @param parameter
     */
    private void updateToolTips() {
      boolean parameter = argDescription.isParameter();
      argValue.setToolTipText(parameter ? "Specifies a constant value for this argument" :
        "Specifies a default value for this argument");
    }
  }
  private final ArgComponents[] argComponentsArray = new ArgComponents[6];
  private TaskDescription taskDescription;
  
  /**
   * Initialize fields
   */
  public ArgDescriptionsEditor() { 
    addComponentsToTaskPanel(new JLabel("Arg Name"), new JLabel("Parameter"), new JLabel("Arg Value"), new JLabel("Action"));
    for (int i = 0; i < argComponentsArray.length; i++) {
      final int index = i;
      ActionListener editAction = new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          ArgDescription argDescription;
          if (index == taskDescription.getArgDescriptionCount()) {
            argDescription = new ArgDescription();
            argDescription.setArgName("<Enter Arg Name>");
            argDescription.setArgValue("<Enter Arg Value>");
            argDescription.setArgFormat("<Enter Arg Format>");
            taskDescription.addArgDescription(argDescription);
            ArgComponents argComponents = argComponentsArray[index];
            argComponents.setValues(argDescription);
            argComponents.setVisible(AS.EDIT);
            if (index + 1 < argComponentsArray.length) 
              argComponentsArray[index + 1].setVisible(AS.NEW);
          } else {
            // Remove
            taskDescription.removeArgDescription(index);
            setTaskDescription(taskDescription);
          }
        }
      };
      ArgComponents argComponents = new ArgComponents(editAction);
      argComponentsArray[i] = argComponents;
      addComponentsToTaskPanel(argComponents.argName, argComponents.argFormat, argComponents.isParameter,
                     argComponents.argValue, argComponents.editButton);
      argComponents.setVisible(AS.BLANK);
    }
  }

  /**
   * @param taskDescription
   */
  public void setTaskDescription(TaskDescription taskDescription) {
    this.taskDescription = taskDescription;
    int count = taskDescription.getArgDescriptionCount();
    for (int i = 0; i < argComponentsArray.length; i++) {
      ArgComponents argComponents = argComponentsArray[i];
      if (i < count) {
        ArgDescription argDescription = taskDescription.getArgDescription(i);
        argComponents.setValues(argDescription);
        argComponents.setVisible(AS.EDIT);
      } else {
        argComponents.setValues(null);
        argComponents.setVisible(i == count ? AS.NEW : AS.BLANK);
      }
    }
  }
}
