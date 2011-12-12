/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.List;


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
  public void run(List<Task> tasks) {
    for (Task task : tasks) {
      task.run();
    }
  }
}
