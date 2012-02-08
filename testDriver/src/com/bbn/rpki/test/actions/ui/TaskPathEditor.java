/*
 * Created on Feb 3, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.Box;
import javax.swing.JComboBox;

import com.bbn.rpki.test.tasks.Breakdown;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.TaskFactory.Task;
import com.bbn.rpki.test.tasks.TaskPath;
import com.bbn.rpki.test.tasks.UploadEpoch;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TaskPathEditor {
  private final Model model;
  private final Box box = Box.createVerticalBox();
  private final List<Breakdown> currentBreakdownPath = new ArrayList<BreakDown>();

  private final List<JComboBox> selectors = new ArrayList<JComboBox>();

  /**
   * @param model
   */
  public TaskPathEditor(Model model) {
    this.model = model;
  }

  /**
   * @param taskPath
   */
  public void setTaskPath(TaskPath taskPath) {
    box.removeAll();
    String rootClassName = getTaskPackageName() + "." + taskPath.getPath()[0];
    @SuppressWarnings("unchecked")
    Class<? extends TaskFactory> taskClass = (Class<? extends TaskFactory>) Class.forName(rootClassName);
    TaskFactory factory = model.getTaskFactory(taskClass);
    for (int i = 0, n = taskPath.getPath().length / 2; i < n; i++) {
      final int pairIndex = i;
      String taskElement = taskPath.getPath()[i * 2];
      Collection<Breakdown> breakdowns = factory.getBreakdowns();
      final JComboBox comboBox = new JComboBox(breakdowns.toArray(new Breakdown[breakdowns.size()]));
      comboBox.setSelectedItem(factory.getBreakdown(taskElement));
      comboBox.addActionListener(new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          String taskName = comboBox.getSelectedItem();
          if (taskName != taskElement) {
            // Selected task name has changed
            if (selectedBreakdown !=
          }
        }))
        String[] options = {
        "UploadEpoch"
      };
      addTaskSelector(taskPath, 0, options);
      }

      /**
       * @return
       */
      private String getTaskPackageName() {
        String s = Task.class.getName();
        int lastDot = s.lastIndexOf(".");
        return s.substring(0, lastDot);
      }

      private void addTaskSelector(TaskPath taskPath, int index, String...options) {
        String s = taskPath.getPath()[index];
        JComboBox comboBox = new JComboBox(options);
        comboBox.setSelectedItem(s);
      }

    }
