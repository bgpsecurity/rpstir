/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a particular breakdown of a task
 *
 * @author tomlinso
 */
public class TaskBreakdown {
  private final List<TaskFactory.Task> tasks;
  private Map<String, TaskFactory.Task> taskMap = null;
  private final String breakdownName;
  private final TaskFactory.Task parentTask;

  /**
   * @param breakdownName
   * @param parentTask
   * @param tasks
   */
  public TaskBreakdown(String breakdownName, TaskFactory.Task parentTask, TaskFactory.Task...tasks) {
    this(breakdownName, parentTask, Arrays.asList(tasks));
  }

  /**
   * @param breakdownName
   * @param parentTask
   * @param tasks
   */
  public TaskBreakdown(String breakdownName, TaskFactory.Task parentTask, List<TaskFactory.Task> tasks) {
    super();
    this.breakdownName = breakdownName;
    this.parentTask = parentTask;
    this.tasks = tasks;
  }

  /**
   * @param taskName
   * @return the named task or null if none found
   */
  public TaskFactory.Task getTask(String taskName) {
    if (taskMap == null) {
      taskMap = new HashMap<String, TaskFactory.Task>();
      for (TaskFactory.Task task : tasks) {
        taskMap.put(task.getTaskName(), task);
      }
    }
    return taskMap.get(taskName);
  }

  /**
   * @return the tasks
   */
  public List<TaskFactory.Task> getTasks() {
    return tasks;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return "Breakdown " + breakdownName + " for " + parentTask.getTaskName();
  }
}
