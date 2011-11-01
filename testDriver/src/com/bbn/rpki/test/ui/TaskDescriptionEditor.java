/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.bbn.rpki.test.model.ArgDescription;
import com.bbn.rpki.test.model.TaskDescription;
import com.bbn.rpki.test.model.TestModel;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class TaskDescriptionEditor extends PropertiesEditor {

  static class ArgComponents {
    private final JLabel argNameLabel = new JLabel("Arg Name");
    private final JLabel argName = new JLabel();
    private final JLabel argType = new JLabel();
    private final JLabel argValue = new JLabel();
    private final JButton editButton;
    ArgComponents(ActionListener editAction) {
      editButton = new JButton("Edit");
      editButton.addActionListener(editAction);
    }
    
    void setVisible(boolean b, boolean b2) {
      argNameLabel.setEnabled(b);
      argName.setEnabled(b);
      argType.setEnabled(b);
      argValue.setEnabled(b);
      editButton.setEnabled(b2);
      if (b2) {
        editButton.setText(b ? "Edit" : "New");
      } else {
        editButton.setText("");
      }
    }

    /**
     * @param argDescription
     */
    public void setValues(ArgDescription argDescription) {
      if (argDescription != null) {
        argName.setText(argDescription.getArgName());
        argValue.setText(argDescription.getArgValue());
        argType.setText(argDescription.isParameter() ? "Parameter" : "Default");
      } else {
        argName.setText("");
        argValue.setText("");
        argType.setText("");
      }
    }
  }
  
  private final JTextField nameField = new JTextField(40);
  private final JTextField scriptField = new JTextField(40);
  private final JTextArea descriptionArea = new JTextArea();
  private final JScrollPane descriptionPane = 
    new JScrollPane(descriptionArea, 
                    JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
  private final ArgDescriptionEditor argDescriptionEditor;
  private TaskDescription selectedTaskDescription;
  private final ArgComponents[] argComponentsArray = new ArgComponents[6];

  /**
   * @param testModel
   * @param taskDescriptionsEditor
   */
  public TaskDescriptionEditor(TestModel testModel, TaskDescriptionsEditor taskDescriptionsEditor) {
    super(testModel, taskDescriptionsEditor);
    argDescriptionEditor = new ArgDescriptionEditor(testModel, taskDescriptionsEditor);
    initTaskPanel();
  }
  
  /**
   * 
   */
  private void initTaskPanel() {
    nameField.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        String newName = nameField.getText();
        String err = testModel.renameTaskDescription(newName, selectedTaskDescription);
        if (err == null) {
          taskDescriptionsEditor.populateTaskList(selectedTaskDescription);
        } else {
          JOptionPane.showMessageDialog(getComponent(), err, "Rename Failed", JOptionPane.ERROR_MESSAGE);
        }
      }
    });
    addToTaskPanel("Name", nameField);
    addToTaskPanel("Description", descriptionPane);
    JPanel scriptPanel = new JPanel();
    scriptPanel.add(scriptField);
    Action changeScriptAction = new AbstractAction("Change...") {
      
      @Override
      public void actionPerformed(ActionEvent e) {
        int option = fileChooser.showOpenDialog(getComponent());
        if (option == JFileChooser.APPROVE_OPTION) {
          selectedTaskDescription.setScriptFile(fileChooser.getSelectedFile());
        }
      }
    };
    scriptPanel.add(new JButton(changeScriptAction));
    addToTaskPanel("Executable", scriptPanel);
    for (int i = 0; i < argComponentsArray.length; i++) {
      final int index = i;
      ActionListener editAction = new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          ArgDescription argDescription;
          if (index == selectedTaskDescription.getArgDescriptionCount()) {
            argDescription = new ArgDescription();
            argDescription.setArgName("Arg");
            argDescription.setArgValue("Value");
            selectedTaskDescription.addArgDescription(argDescription);
            ArgComponents argComponents = argComponentsArray[index];
            argComponents.setValues(argDescription);
            argComponents.setVisible(true, true);
            
          }
          argDescription = selectedTaskDescription.getArgDescription(index);
          argDescriptionEditor.setArgDescription(argDescription);
        }
      };
      ArgComponents argComponents = new ArgComponents(editAction);
      argComponentsArray[i] = argComponents;
      addToTaskPanel(argComponents.argNameLabel, argComponents.argName, argComponents.argType,
                     argComponents.argValue, argComponents.editButton);
      argComponents.setVisible(false, false);
    }
    addToTaskPanel("Arg Editor", argDescriptionEditor.getComponent());
  }

  /**
   * @param selectedTaskDescription
   */
  public void showTaskDescription(TaskDescription selectedTaskDescription) {
    this.selectedTaskDescription = selectedTaskDescription;
    if (selectedTaskDescription == null) {
      initTextField(nameField, null);
      initTextField(descriptionArea, null);
    } else {
      initTextField(nameField, selectedTaskDescription.getName());
      initTextField(descriptionArea, selectedTaskDescription.getDescription());
      descriptionArea.setEnabled(true);
      int count = selectedTaskDescription.getArgDescriptionCount();
      for (int i = 0; i < argComponentsArray.length; i++) {
        ArgComponents argComponents = argComponentsArray[i];
        if (i < count) {
          ArgDescription argDescription = selectedTaskDescription.getArgDescription(i);
          argComponents.setValues(argDescription);
          argComponents.setVisible(true, true);
        } else {
          argComponents.setValues(null);
          argComponents.setVisible(false, i == count);
        }
      }
    }
  }
}
