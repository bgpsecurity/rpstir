/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;

/**
 * Performs the second simplest possible execution of the model by initializing
 * and then uploading everything and updating the cache for every epoch. All
 * tasks are broken down as far as possible.
 *
 * @author tomlinso
 */
public class TestUpdateEveryStep extends TestExpanded {
  
  /**
   * @param model
   */
  public TestUpdateEveryStep(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.Test#shouldUpdateCache(com.bbn.rpki.test.tasks.Task)
   */
  @Override
  protected boolean shouldUpdateCache(Task task) {
    return true;
  }
}
