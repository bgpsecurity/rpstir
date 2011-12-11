/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.tasks;


/**
 * The task executor
 *
 * @author RTomlinson
 */
public class TaskExecutor {

  private final Model model;

  /**
   * @param model 
   */
  public TaskExecutor(Model model) {
    this.model = model;
  }

  /**
   * runs the task
   * @param topTask
   */
  public void run(Task topTask) {
    for (int epochIndex = 0, nEpochs = model.getEpochCount(); epochIndex < nEpochs; epochIndex++) {
      topTask.run(epochIndex);
    }
  }
}
