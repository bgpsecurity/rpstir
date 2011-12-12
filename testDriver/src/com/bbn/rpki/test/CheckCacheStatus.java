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
    String[] cmd = {
        "run_scripts/results.py"
    };
    Util.exec(cmd, "Reports", false, null, null);
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

}
