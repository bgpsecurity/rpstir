/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.TaskBreakdown;

/**
 * The base of all tests. Maintains the task list.
 *
 * @author tomlinso
 */
public class Test {
  protected Model model;

  protected Test(Model model) {
    this.model = model;
  }

  /**
   * Override this to break down tasks differently
   * @param task
   * @return the TaskBreakdown (null by default)
   */
  protected TaskBreakdown getTaskBreakdown(TaskFactory task) {
    return null;
  }
}
