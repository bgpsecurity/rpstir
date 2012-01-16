/*
 * Created on Jan 13, 2012
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.Test;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class AdvanceEpoch extends Task {

  private final Model model;
  private final Test test;

  /**
   * @param model
   * @param test
   */
  public AdvanceEpoch(Model model,Test test) {
    this.model = model;
    this.test = test;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    model.advanceEpoch();
    if (model.getEpochIndex() + 1 < model.getEpochCount()) {
      test.addTask(this);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert false;
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return null;
  }

}
