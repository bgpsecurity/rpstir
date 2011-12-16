/*
 * Created on Dec 11, 2011
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.objects.Util;

/**
 * A Task to run the chaser to download and store into the cache
 *
 * @author tomlinso
 */
public class UpdateCache extends Task {
  private final Model model;
  
  /**
   * @param model
   */
  public UpdateCache(Model model) {
    this.model = model;
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    Util.exec("Chaser", false, Util.RPKI_ROOT, null,
              "rsync_aur/rsync_listener",
              "proto/chaser",
              "-f", "initial_rsync.config");
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
