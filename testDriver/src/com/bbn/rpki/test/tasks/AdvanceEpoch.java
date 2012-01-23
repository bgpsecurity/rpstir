/*
 * Created on Jan 13, 2012
 */
package com.bbn.rpki.test.tasks;


/**
 * Advances to the next epoch and sets up the standard tasks for that epoch
 * including the next AdvanceEpoch task if there are more epochs to follow.
 *
 * @author tomlinso
 */
public class AdvanceEpoch extends Task {

  private final Model model;

  /**
   * @param model
   */
  public AdvanceEpoch(Model model) {
    super("AdvanceEpoch", model);
    this.model = model;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    model.advanceEpoch();
    if (model.getEpochIndex() + 1 < model.getEpochCount()) {
      model.addTask(this);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return null;
  }
}
