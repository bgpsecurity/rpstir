/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.objects.Util;

/**
 * Checks the cache for agreement with the most recent uploads.
 *
 * @author tomlinso
 */
public class CheckCacheStatus extends Task {

  /**
   * @param model
   */
  public CheckCacheStatus(Model model) {
    super("CheckCacheStatus", model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    Util.exec("Reports", false, Util.RPKI_ROOT, null, null, "run_scripts/results.py", "-v");
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return null;
  }
}
