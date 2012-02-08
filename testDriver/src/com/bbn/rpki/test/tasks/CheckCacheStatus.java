/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Checks the cache for agreement with the most recent uploads.
 *
 * @author tomlinso
 */
public class CheckCacheStatus extends TaskFactory {

  protected class Task extends TaskFactory.Task {
    protected Task() {
      super("CheckCacheStatus");
    }

    @Override
    public void run() {
      Util.exec("Reports", false, Util.RPKI_ROOT, null, null, "run_scripts/results.py", "-v");
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
  public CheckCacheStatus(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns here
  }

  /**
   * @return a new Task
   */
  @Override
  public Task createTask(String taskName) {
    return new Task();
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    // Should not appear in a TaskPath
    return Collections.singleton("CheckCacheStatus");
  }
}
