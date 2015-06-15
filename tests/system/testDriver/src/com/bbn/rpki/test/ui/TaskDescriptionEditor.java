/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.bbn.rpki.test.model.TaskDescription;
import com.bbn.rpki.test.model.TestModel;

/**
 * Provides a component for editing a TaskDescription.
 * 
 * Provides text fields and areas for editing the name, description,
 * and so forth.
 *
 * @author RTomlinson
 */
public class TaskDescriptionEditor extends PropertiesEditor {

  
  private final JTextField nameField = new JTextField(40);
  private final JTextField scriptField = new JTextField(40);
  private final JTextArea descriptionArea = new JTextArea();
  private final JScrollPane descriptionPane = 
    new JScrollPane(descriptionArea, 
                    JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
  private TaskDescription selectedTaskDescription;
  private final ArgDescriptionsEditor argDescriptionsEditor;
  private final TestModel testModel;
  private final TaskDescriptionsEditor taskDescriptionsEditor;
  private final Action viewScriptAction = new AbstractAction("View") {
    
    @Override
    public void actionPerformed(ActionEvent e) {
      viewScriptFile(selectedTaskDescription.getScriptFile());
    }
  };
  private final Action changeScriptAction = new AbstractAction("Change...") {
    
    @Override
    public void actionPerformed(ActionEvent e) {
      int option = fileChooser.showOpenDialog(getComponent());
      if (option == JFileChooser.APPROVE_OPTION) {
        selectedTaskDescription.setScriptFile(fileChooser.getSelectedFile());
        updateScriptFile();
      }
    }
  };

  /**
   * @param testModel
   * @param taskDescriptionsEditor
   */
  public TaskDescriptionEditor(TestModel testModel, TaskDescriptionsEditor taskDescriptionsEditor) {
    this.testModel = testModel;
    this.taskDescriptionsEditor = taskDescriptionsEditor;
    this.argDescriptionsEditor = new ArgDescriptionsEditor();
    viewScriptAction.setEnabled(false);
    initTaskPanel();
  }
  
  /**
   * 
   */
  private void initTaskPanel() {
    descriptionPane.setPreferredSize(new Dimension(400, 60));
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
    scriptPanel.add(new JButton(changeScriptAction));
    scriptPanel.add(new JButton(viewScriptAction));
    addToTaskPanel("Executable", scriptPanel);
    addComponentsToTaskPanel(argDescriptionsEditor.getComponent());              
  }

  /**
   * @param scriptFile
   */
  protected void viewScriptFile(File scriptFile) {
    try {
      new TextFileViewer(scriptFile);
    } catch (IOException e) {
      JOptionPane.showMessageDialog(getComponent(), e.getMessage(), "Exception Reading File", JOptionPane.WARNING_MESSAGE);
    }
  }

  /**
   * @param selectedTaskDescription
   */
  public void showTaskDescription(TaskDescription selectedTaskDescription) {
    this.selectedTaskDescription = selectedTaskDescription;
    if (selectedTaskDescription == null) {
      initTextField(nameField, null);
      initTextField(descriptionArea, null);
      initTextField(scriptField, null);
    } else {
      initTextField(nameField, selectedTaskDescription.getName());
      initTextField(descriptionArea, selectedTaskDescription.getDescription());
      descriptionArea.setEnabled(true);
      updateScriptFile();
    }
    argDescriptionsEditor.setTaskDescription(selectedTaskDescription);
  }

  /**
   */
  private void updateScriptFile() {
    File scriptFile = selectedTaskDescription.getScriptFile();
    if (scriptFile != null) {
      initTextField(scriptField, scriptFile.getPath());
      viewScriptAction.setEnabled(scriptFile.canRead());
    } else {
      initTextField(scriptField, null);
      viewScriptAction.setEnabled(false);
    }
  }
}
