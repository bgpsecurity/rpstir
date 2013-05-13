/*
 * Created on Feb 3, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.Box;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

import com.bbn.rpki.test.tasks.Breakdown;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.TaskFactory.Task;
import com.bbn.rpki.test.tasks.TaskPath;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TaskPathEditor {
  private static class Item {
    JComboBox comboBox;
    Task task;
    Breakdown breakdown;

    @Override
    public String toString() {
      if (breakdown != null) {
        return breakdown.getBreakdownName();
      }
      return task.getTaskName();
    }

    /**
     * @return true if this item is valid
     * Only the last item can be invalid.
     */
    public boolean isValid() {
      return task != null || breakdown != null;
    }
  }
  private final Model model;
  private final Box box = Box.createVerticalBox();
  private final List<Item> items = new ArrayList<Item>();
  private final List<ActionListener> listeners = new ArrayList<ActionListener>(1);

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
    items.clear();
    String[] path = taskPath.getPath();
    if (path.length == 0) {
      // Brand new path has nothing
      addBase(null, 0);
      path = new String[] {
          items.get(0).task.getTaskName()
      };
    } else {
      addBase(path[0], 0);
    }
    for (int i = 1; i < path.length; i++) {
      if (i % 2 == 1) {
        addBreakdown(path[i], i);
      } else {
        addTaskFactory(path[i], i);
      }
    }
    if (path.length % 2 == 1) {
      addBreakdown(null, path.length);
    } else {
      addTaskFactory(null, path.length);
    }
  }

  @SuppressWarnings("unchecked")
  private void addBase(String name0, int index) {
    assert index == 0;
    Item item = new Item();
    TaskFactory.Task[] topTasks = getTopTasks();
    item.comboBox = new JComboBox(topTasks);
    if (name0 != null) {
      int lp = name0.indexOf("(");
      name0 = name0.substring(0, lp);
      String rootClassName = getTaskPackageName() + "." + name0;
      Class<? extends TaskFactory> taskClass;
      try {
        taskClass = (Class<? extends TaskFactory>) Class.forName(rootClassName);
      } catch (ClassNotFoundException e) {
        throw new RuntimeException(e);
      }
      item.task = model.getTaskFactory(taskClass).createTask(name0);
    } else {
      item.task = topTasks[0];
    }
    addItem(item);
  }

  private TaskFactory.Task[] getTopTasks() {
    return model.getTopTasks();
  }

  private void addBreakdown(String breakdownName, final int index) {
    assert index % 2 == 1;
    Item previousItem = items.get(index - 1);
    final TaskFactory factory = previousItem.task.getTaskFactory();
    Collection<Breakdown> breakdowns = factory.getBreakdowns();
    if (breakdowns.isEmpty()) {
      assert breakdownName == null;
      return;
    }
    final Item item = new Item();
    item.comboBox = createComboBox(breakdowns);
    if (breakdownName == null) {
      item.breakdown = null;
    } else {
      final Breakdown currentBreakdown = factory.getBreakdown(breakdownName);
      item.breakdown = currentBreakdown;
      item.comboBox.setSelectedItem(currentBreakdown);
    }
    item.comboBox.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        Object selection = item.comboBox.getSelectedItem();
        if (selection instanceof String) {
          selection = null;
        }
        if (item.breakdown != selection) {
          item.breakdown = (Breakdown) selection;
          removeItems(items.subList(index + 1, items.size()));
          if (item.breakdown != null) {
            addTaskFactory(null, index + 1);
            fireListeners();
          }
        }
      }
    });
    addItem(item);
  }

  /**
   * @param items
   * @return the combo box
   */
  public JComboBox createComboBox(Collection<?> items) {
    Object[] model = new Object[items.size() + 1];
    int ix = 0;
    model[ix++] = "<Nothing Selected>";
    for (Object o : items) {
      model[ix++] = o;
    }
    return new JComboBox(model);
  }

  private void addTaskFactory(String taskName, final int index) {
    assert index % 2 == 0;
    Item previousItem = items.get(index - 1);
    Item previousTaskItem = items.get(index - 2);
    Breakdown breakdown = previousItem.breakdown;
    final Item item = new Item();
    TaskBreakdown taskBreakdown = breakdown.getTaskBreakdown(previousTaskItem.task);
    List<TaskFactory.Task> tasks = taskBreakdown.getTasks();
    item.comboBox = createComboBox(tasks);
    if (taskName == null) {
      item.task = null;
    } else {
      item.task = taskBreakdown.getTask(taskName);
      item.comboBox.setSelectedItem(item.task);
    }
    item.comboBox.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        Object selection = item.comboBox.getSelectedItem();
        if (selection == null || selection instanceof String) {
          if (item.task != null) {
            item.comboBox.setSelectedItem(item.task);
          }
          return;
        }
        TaskFactory.Task task = (Task) selection;
        if (item.task != task) {
          item.task = task;
          removeItems(items.subList(index + 1, items.size()));
          addBreakdown(null, index + 1);
          fireListeners();
        }
      }
    });
    addItem(item);
  }

  /**
   * @param ret
   */
  public void addItem(final Item ret) {
    box.add(ret.comboBox);
    items.add(ret);
    box.revalidate();
    box.repaint();
    fireListeners();
  }

  /**
   * 
   */
  public void fireListeners() {
    for (ActionListener l : listeners) {
      l.actionPerformed(null);
    }
  }

  /**
   * @param subList
   */
  protected void removeItems(List<Item> subList) {
    for (Item item : subList) {
      box.remove(item.comboBox);
    }
    subList.clear();
  }

  /**
   * @return
   */
  private String getTaskPackageName() {
    String s = Task.class.getName();
    int lastDot = s.lastIndexOf(".");
    return s.substring(0, lastDot);
  }

  /**
   * @param c
   * @return the selected CA_Object or null for no selection
   */
  public TaskPath showDialog(Component c) {
    JOptionPane optionPane =
      new JOptionPane(box,
                      JOptionPane.QUESTION_MESSAGE,
                      JOptionPane.OK_CANCEL_OPTION,
                      null, null, null);
    JDialog dialog = optionPane.createDialog(c, "Select a Task");
    dialog.setResizable(true);
    dialog.setVisible(true);
    dialog.dispose();
    Object value = optionPane.getValue();
    // Should be Integer unless aborted
    if (value != null) {
      int option = (Integer) value;
      if (option == JOptionPane.OK_OPTION) {
        String[] path = new String[items.size()];
        for (int i = 0; i < path.length; i++) {
          path[i] = items.get(i).toString();
        }
        return new TaskPath(path);
      }
    }
    return null;
  }

  /**
   * @return the component
   */
  public Component getComponent() {
    return box;
  }

  /**
   * @param actionListener
   */
  public void addActionListener(ActionListener actionListener) {
    listeners.add(actionListener);
  }

  /**
   * @return the current TaskPath
   */
  public TaskPath getTaskPath() {
    int size = items.size();
    if (!items.get(size - 1).isValid()) {
      size -= 1;
    }
    String[] path = new String[size];
    for (int i = 0; i < path.length; i++) {
      path[i] = items.get(i).toString();
    }
    return new TaskPath(path);
  }
}
