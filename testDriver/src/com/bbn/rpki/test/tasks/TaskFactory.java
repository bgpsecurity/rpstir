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
 * The interface for all tasks
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

    private final String taskName;

    private boolean testEnabled;

    private TaskBreakdown selectedTaskBreakdown = null;

    protected Task(String taskName) {
      this.taskName = taskName;
    }

    /**
     * @return the name of this task (for indexing)
     */
    public String getTaskName() {
      return taskName;
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
      String logDetail = getLogDetail();
      return getClass().getSimpleName() + (logDetail == null ? "" : " " + logDetail);
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
   * @param taskName
   * @return a Task
   */
  public abstract Task createTask(String taskName);

  /**
   * @return the breakdown names available from this factory
   */
  public Collection<Breakdown> getBreakdowns() {
    return getBreakdownMap().values();
  }

  /**
   * @return then possible names of tasks
   */
  public abstract Collection<String> getTaskNames();

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
