/*
 * Created on Jan 13, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.Collection;
import java.util.Collections;
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
    protected Task() {
      super(TASK_NAME);
    }

    @Override
    public void run() {
      model.advanceEpoch();
      if (model.getEpochIndex() < model.getEpochCount()) {
        model.addTask(this);
      }
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return String.valueOf(model.getEpochIndex());
    }
  }

  private static final String TASK_NAME = "";

  /**
   * @param model
   */
  public AdvanceEpoch(Model model) {
    super(model);
  }

  @Override
  protected Task reallyCreateTask(String taskName) {
    assert TASK_NAME.equals(taskName);
    return new Task();
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns here
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    return Collections.singleton(TASK_NAME);
  }
}
