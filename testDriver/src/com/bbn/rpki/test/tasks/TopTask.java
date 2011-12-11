/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.List;


/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TopTask implements Task {
  private final List<Task> tasks = new ArrayList<Task>();
  
  /**
   * Construct top-level tasks
   * @param model
   */
  public TopTask(Model model) {
    tasks.add(new ReinitializeCache(model));
    tasks.add(new InstallTrustAnchor(model));
    tasks.add(new UploadEpoch(model));
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
      for (Task task : tasks) {
        task.run(epochIndex);
      }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    // TODO Auto-generated method stub
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    // TODO Auto-generated method stub
    return null;
  }

}
