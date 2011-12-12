/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;

/**
 * Performs the second simplest possible execution of the model by initializing
 * and then uploading everything and updating the cache for every epoch. All
 * tasks are broken down as far as possible.
 *
 * @author tomlinso
 */
public class TestExpanded extends Test {
  
  /**
   * @param model
   */
  public TestExpanded(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.Test#getTaskBreakdown(com.bbn.rpki.test.tasks.Task)
   */
  @Override
  protected TaskBreakdown getTaskBreakdown(Task task) {
    if (task.getBreakdownCount() > 0) {
      return task.getTaskBreakdown(0);
    }
    return null;
  }
}
