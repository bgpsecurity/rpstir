/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.List;


/**
 * Run the cache updater
 *
 * @author tomlinso
 */
public class TopTask extends Task {
  private final List<Task> tasks = new ArrayList<Task>();
  
  /**
   * Construct top-level tasks
    tasks.add(new ReinitializeCache(model));
    tasks.add(new InstallTrustAnchor(model));
    for (int epochIndex = 0; epochIndex < model.getEpochCount(); epochIndex++) {
      tasks.add(new UploadEpoch(model, epochIndex));
      tasks.add(new UpdateCache(model));
    }
   * @param model
   */
  public TopTask(Model model) {
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
      for (Task task : tasks) {
        task.run();
      }
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

}
