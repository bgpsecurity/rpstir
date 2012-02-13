/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;


/**
 * The interface for all tasks.
 * 
 * Tasks have names composed of the name of the TaskFactory and a
 * factory-relative part. Generally, factory-relative names are used with a Task
 * and its factory and full names are used externally. The form of a full name
 * is:
 *    TaskFactory(relativePart)
 * TaskFactory provides convenience functions for conversion
 * from factory-relative names to full names and vice versa.
 *
 * @author tomlinso
 */
public abstract class TaskFactory {
  /**
   * All Tasks are inner classes of TaskFactorys.
   *
   * @author tomlinso
   */
  public abstract class Task {

    private final String relativeTaskName;

    private boolean testEnabled;

    private TaskBreakdown selectedTaskBreakdown = null;

    protected Task(String relativeTaskName) {
      this.relativeTaskName = relativeTaskName;
    }

    /**
     * @return the full name of this task (for indexing)
     */
    public String getTaskName() {
      return TaskFactory.this.getClass().getSimpleName() + "(" + relativeTaskName +")";
    }

    /**
     * @return the TaskFactory for this Task
     */
    public TaskFactory getTaskFactory() {
      return TaskFactory.this;
    }

    /**
     * @param b
     */
    public void setTestEnabled(boolean b) {
      this.testEnabled = b;
    }

    /**
     * @return the testEnabled
     */
    public boolean isTestEnabled() {
      return testEnabled;
    }

    /**
     * Runs the task
     */
    public abstract void run();

    /**
     * @param breakdownName
     * @return the specified TaskBreakdown
     */
    protected final TaskBreakdown getTaskBreakdown(String breakdownName) {
      return TaskFactory.this.getBreakdownMap().get(breakdownName).getTaskBreakdown(this);
    }

    protected abstract String getLogDetail();

    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public final String toString() {
      return getTaskName();
    }

    /**
     * @param selectedTaskBreakdown the selectedTaskBreakdown to set
     */
    public void setSelectedTaskBreakdown(TaskBreakdown selectedTaskBreakdown) {
      this.selectedTaskBreakdown = selectedTaskBreakdown;
    }

    /**
     * @return the selectedTaskBreakdown
     */
    public TaskBreakdown getSelectedTaskBreakdown() {
      return selectedTaskBreakdown;
    }

    /**
     * @param string
     * @return the newly selected breakdown
     */
    public TaskBreakdown selectTaskBreakdown(String string) {
      selectedTaskBreakdown = getTaskBreakdown(string);
      return selectedTaskBreakdown;
    }

  }

  protected final Model model;
  private Map<String, Breakdown> breakdownMap = null;

  protected TaskFactory(Model model) {
    this.model = model;
  }

  /**
   * @return the only Task this factory creates
   */
  public final Task createOnlyTask() {
    Collection<String> allowedNames = getTaskNames();
    assert allowedNames != null && allowedNames.size() == 1;
    return createTask(allowedNames.iterator().next());
  }

  /**
   * @param relativeTaskName
   * @return
   */
  public final Task createRelativeTask(String relativeTaskName) {
    assert getRelativeTaskNames().contains(relativeTaskName);
    return reallyCreateTask(relativeTaskName);
  }

  /**
   * @param taskName a full task name
   * @return a Task
   */
  public final Task createTask(String taskName) {
    String relativeTaskName = relativeTaskName(taskName);
    return reallyCreateTask(relativeTaskName);
  }

  protected abstract Task reallyCreateTask(String relativeTaskName);

  private String relativeTaskName(String taskName) {
    String className = TaskFactory.this.getClass().getSimpleName();
    String relativeTaskName = null;
    if (taskName.startsWith(className)) {
      String rest = taskName.substring(className.length());
      if (rest.isEmpty()) {
        relativeTaskName = "";
      } else {
        if (rest.startsWith("(") && rest.endsWith(")")) {
          relativeTaskName = rest.substring(1, rest.length() - 1);
        }
      }
    }
    assert relativeTaskName != null;
    assert getRelativeTaskNames().contains(relativeTaskName);
    return relativeTaskName;
  }


  /**
   * @return the breakdown names available from this factory
   */
  public Collection<Breakdown> getBreakdowns() {
    return getBreakdownMap().values();
  }

  /**
   * @return the allowed full names of tasks
   */
  public final Collection<String> getTaskNames() {
    Collection<String> relativeTaskNames = getRelativeTaskNames();
    List<String> ret = new ArrayList<String>(relativeTaskNames.size());
    for (String relativeTaskName : relativeTaskNames) {
      ret.add(String.format("%s(%s)", getClass().getSimpleName(), relativeTaskName));
    }
    return ret;
  }

  protected abstract Collection<String> getRelativeTaskNames();

  /**
   * @param breakdownName
   * @return the Breakdown with the specified name
   */
  public Breakdown getBreakdown(String breakdownName) {
    return getBreakdownMap().get(breakdownName);
  }

  /**
   * @return the breakdown map. Create if not yet created.
   */
  private Map<String, Breakdown> getBreakdownMap() {
    if (breakdownMap == null) {
      breakdownMap  = new TreeMap<String, Breakdown>();
      List<Breakdown> list = new ArrayList<Breakdown>();
      appendBreakdowns(list);
      for (Breakdown breakdown : list) {
        breakdownMap.put(breakdown.getBreakdownName(), breakdown);
      }
    }
    return breakdownMap;
  }

  protected abstract void appendBreakdowns(List<Breakdown> list);

  /**
   * @return the model
   */
  public Model getModel() {
    return model;
  }
}
