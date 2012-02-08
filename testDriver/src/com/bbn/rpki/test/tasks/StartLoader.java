/*
 * Created on Jan 18, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.RunLoader;

/**
 * Start the loader process.
 * 
 * This is not actually used as a Task and may go away
 *
 * @author tomlinso
 */
public class StartLoader extends TaskFactory {
  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task() {
      super(TASK_NAME);
    }

    @Override
    public void run() {
      RunLoader.singleton().start();
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return "Loader started";
    }
  }

  static final String TASK_NAME = "StartLoader";

  /**
   * @param model
   */
  public StartLoader(Model model) {
    super(model);
  }

  /**
   * @return a new Task
   */
  @Override
  public Task createTask(String taskName) {
    return new Task();
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    return Collections.singleton(TASK_NAME);
  }
}

