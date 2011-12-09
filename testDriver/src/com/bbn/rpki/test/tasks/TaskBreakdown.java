/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TaskBreakdown {
  enum Type {
    SEQUENCE,
    SHUFFLE,
    PARALLEL
  }
  private final List<Task> tasks;
  private final Type type;
  /**
   * @param tasks
   * @param type
   */
  public TaskBreakdown(List<Task> tasks, Type type) {
    super();
    this.tasks = tasks;
    this.type = type;
  }
  /**
   * @return the tasks
   */
  public List<Task> getTasks() {
    return tasks;
  }
  /**
   * @return the type
   */
  public Type getType() {
    return type;
  }
}
