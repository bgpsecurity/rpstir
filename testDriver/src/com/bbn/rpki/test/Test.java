/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.tasks.InitializeCache;
import com.bbn.rpki.test.tasks.InstallTrustAnchor;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.UpdateCache;
import com.bbn.rpki.test.tasks.UploadEpoch;

/**
 * The base of all tests. Maintains the task list.
 *
 * @author tomlinso
 */
public class Test {
  protected List<Task> tasks = new ArrayList<Task>();
  protected Model model;
  
  protected Test(Model model) {
    this.model = model;
    tasks.add(new InitializeCache(model));
    tasks.add(new InitializeRepositories(model));
    for (int epochIndex = 0; epochIndex < model.getEpochCount(); epochIndex++) {
      breakDown(new UploadEpoch(model, epochIndex));
      if (epochIndex == 0) {
        tasks.add(new InstallTrustAnchor(model));
      }
    }
    tasks.add(new UpdateCache(model));
    tasks.add(new CheckCacheStatus(model));
  }
  
  private void breakDown(Task task) {
    int breakdownCount = task.getBreakdownCount();
    TaskBreakdown taskBreakdown;
    if (breakdownCount > 0) {
      taskBreakdown = getTaskBreakdown(task);
    } else {
      taskBreakdown = null;
    }
    if (taskBreakdown == null) {
      addTask(task);
    } else {
      for (Task subtask : taskBreakdown.getTasks()) {
        breakDown(subtask);
      }
    }
  }

  /**
   * Override this to break down tasks differently
   * @param task
   * @return the TaskBreakdown (null by default)
   */
  protected TaskBreakdown getTaskBreakdown(Task task) {
    return null;
  }

  /**
   * @param task
   */
  private void addTask(Task task) {
    tasks.add(task);
    if (shouldUpdateCache(task)) {
      tasks.add(new UpdateCache(model));
      tasks.add(new CheckCacheStatus(model));
    }
  }
  
  /**
   * @param task
   * @return
   */
  protected boolean shouldUpdateCache(Task task) {
    // Update the cache after each epoch, by default
    return task instanceof UploadEpoch;
  }

  /**
   * @return the tasks to execute
   */
  public final List<Task> getTasks() {
    return tasks;
  }
}
