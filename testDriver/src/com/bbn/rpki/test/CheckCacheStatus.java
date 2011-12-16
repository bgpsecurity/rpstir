/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class CheckCacheStatus extends Task {

  /**
   * @param model
   */
  public CheckCacheStatus(Model model) {
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    Util.exec("Reports", false, Util.RPKI_ROOT, null, null, "run_scripts/results.py");
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    // TODO Auto-generated method stub
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    // TODO Auto-generated method stub
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
