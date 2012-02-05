/*
 * Created on Feb 3, 2012
 */
package com.bbn.rpki.test.actions.ui;

import javax.swing.JComboBox;

import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskPath;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TaskPathEditor {
  private final Model model;

  public TaskPathEditor(Model model) {
    this.model = model;
  }

  public void setTaskPath(TaskPath taskPath) {
    String[] options = {
        "UploadEpoch"
    };
    addTaskSelector(taskPath, 0, options);
  }

  private void addTaskSelector(TaskPath taskPath, int index, String...options) {
    String s = taskPath.getPath()[index];
    JComboBox comboBox = new JComboBox(options);
    comboBox.setSelectedItem(s);
  }

}
