/*
 * Created on Jan 13, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.Collection;
import java.util.List;


/**
 * Advances to the next epoch and sets up the standard tasks for that epoch
 * including the next AdvanceEpoch task if there are more epochs to follow.
 *
 * @author tomlinso
 */
public class AdvanceEpoch extends TaskFactory {
  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task(String taskName) {
      super(taskName);
    }

    @Override
    public void run() {
      model.advanceEpoch();
      if (model.getEpochIndex() + 1 < model.getEpochCount()) {
        model.addTask(this);
      }
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return null;
    }
  }

  /**
   * @param model
   */
  public AdvanceEpoch(Model model) {
    super(model);
  }

  /**
   * @return a new AdvanceEpoch.Task
   */
  @Override
  public Task createTask(String taskName) {
    return new Task(taskName);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns here
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    // Should not appear in a TaskPath
    return null;
  }
}
