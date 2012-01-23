/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;


/**
 * The interface for all tasks
 *
 * @author tomlinso
 */
public abstract class Task {

  protected final Model model;

  private final String taskName;

  private Task successTest;

  private TaskBreakdown selectedBreakdown;

  private boolean testEnabled;

  protected Task(String taskName, Model model) {
    this.model = model;
    this.taskName = taskName;
  }

  /**
   * @return the name of this task (for indexing)
   */
  public String getTaskName() {
    return taskName;
  }

  /**
   * @return the successTest
   */
  public Task getSuccessTest() {
    return successTest;
  }

  /**
   * @param successTest the successTest to set
   */
  public void setSuccessTest(Task successTest) {
    this.successTest = successTest;
  }

  /**
   * Runs the task
   */
  public abstract void run();

  /**
   * @param breakdownName
   * @return the specified TaskBreakdown
   */
  protected TaskBreakdown getTaskBreakdown(String breakdownName) {
    assert false;
    return null;
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
   * @param breakdownName
   * @return the selected breakdown
   */
  public TaskBreakdown selectTaskBreakdown(String breakdownName) {
    this.selectedBreakdown = getTaskBreakdown(breakdownName);
    return selectedBreakdown;
  }

  /**
   * @return the selected breakdown or null if none has been selected
   */
  public TaskBreakdown getSelectedBreakdown() {
    return selectedBreakdown;
  }

  /**
   * @param b
   */
  public void setTestEnabled(boolean b) {
    this.testEnabled = b;
  }

  /**
   * @return the model
   */
  public Model getModel() {
    return model;
  }

  /**
   * @return the testEnabled
   */
  public boolean isTestEnabled() {
    return testEnabled;
  }

  /**
   * @param selectedBreakdown the selectedBreakdown to set
   */
  public void setSelectedBreakdown(TaskBreakdown selectedBreakdown) {
    this.selectedBreakdown = selectedBreakdown;
  }
}
