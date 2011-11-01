/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.io.IOException;

import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.jdom.JDOMException;

import com.bbn.rpki.test.model.TaskDescription;
import com.bbn.rpki.test.model.TestModel;
import com.bbn.rpki.test.model.XMLBase;

/**
 * UI for creating a TaskDescription
 *
 * @author RTomlinson
 */
public class TaskDescriptionsEditor implements ListSelectionListener {
  /**
   * 
   */
  private static final String ADD_VALUE = "Add...";
  private final DefaultListModel taskListModel = new DefaultListModel();
  private final JList taskList = new JList(taskListModel);
  private final JScrollPane taskPane = new JScrollPane(taskList);
  private final TestModel testModel;
  private TaskDescription selectedTaskDescription;
  private final JPanel panel = new JPanel(new BorderLayout());
  private final TaskDescriptionEditor taskDescriptionEditor;
  
  /**
   * @param testModel 
   * @throws IOException
   * @throws JDOMException
   */
  public TaskDescriptionsEditor(TestModel testModel) {
    this.testModel = testModel;
    this.taskDescriptionEditor = new TaskDescriptionEditor(testModel, this);
    initTaskList();
    panel.add(taskPane, BorderLayout.WEST);
    panel.add(taskDescriptionEditor.getComponent(), BorderLayout.CENTER);
    taskList.getSelectionModel().addListSelectionListener(this);
  }

  /**
   * 
   */
  private void initTaskList() {
    taskList.setPreferredSize(new Dimension(200, taskList.getPreferredSize().height));
    taskList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    populateTaskList(null);
  }

  /**
   * 
   */
  void populateTaskList(XMLBase selectTaskDescription) {
    taskListModel.clear();
    taskListModel.addElement(ADD_VALUE);
    for (XMLBase taskDescription : this.testModel.getTaskDescriptions()) {
      taskListModel.addElement(taskDescription);
    }
    if (selectTaskDescription != null) {
      taskList.setSelectedValue(selectTaskDescription, true);
    }
  }
  
  /**
   * @return the UI component
   */
  public Component getComponent() {
    return panel;
  }

  /**
   * @see javax.swing.event.ListSelectionListener#valueChanged(javax.swing.event.ListSelectionEvent)
   */
  @Override
  public void valueChanged(ListSelectionEvent e) {
    if (e.getValueIsAdjusting()) return;
    Object selectedValue = taskList.getSelectedValue();
    if (ADD_VALUE.equals(selectedValue)) {
      TaskDescription taskDescription = new TaskDescription(testModel.genNewTaskName(),
                                                    "<Enter task description>");
      testModel.addTaskDescription(taskDescription);
      taskListModel.addElement(taskDescription);
      taskList.setSelectedValue(taskDescription, true);
    } else {
      selectedTaskDescription = (TaskDescription) selectedValue;
      showSelectedTaskDescription();
    }
  }

  /**
   * @param selectedTaskDescription
   */
  private void showSelectedTaskDescription() {
    taskDescriptionEditor.showTaskDescription(selectedTaskDescription);
  }
}
