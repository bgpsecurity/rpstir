/*
 * Created on Dec 11, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * A Task to run the chaser to download and store into the cache
 *
 * @author tomlinso
 */
public class UpdateCache extends TaskFactory {
  /**
   * 
   */
  static final String TASK_NAME = "Update Cache";

  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task() {
      super(TASK_NAME);
    }

    @Override
    public void run() {
      Util.exec("Chaser", false, Util.RPKI_ROOT, null,
                "rsync_aur/rsync_listener",
                "proto/chaser",
                "-f", "initial_rsync.config");
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
  public UpdateCache(Model model) {
    super(model);
  }

  /**
   * @param taskName
   * @return a new UpdateCache.Task
   */
  @Override
  public Task createTask(String taskName) {
    assert TASK_NAME.equals(taskName);
    return new Task();
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns to append
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    return Collections.singleton(TASK_NAME);
  }
}
