/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class CompoundTask extends Task {

  protected List<Task> tasks = new ArrayList<Task>();
  
  private final TaskBreakdown.Type type;
  
  protected CompoundTask(TaskBreakdown.Type type) {
    this.type = type;
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
    return 1;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    return new TaskBreakdown(tasks, type);
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#toString()
   */
  @Override
  public String getLogDetail() {
    StringBuilder sb = new StringBuilder();
    for (Task task : tasks) {
      sb.append("\n  ");
      sb.append(task.toString());
    }
    return sb.toString();
  }
}
