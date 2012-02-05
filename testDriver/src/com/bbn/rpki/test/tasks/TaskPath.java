/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.tasks;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TaskPath {
  private final String[] path;

  /**
   * @param path
   */
  public TaskPath(String path) {
    this.path = path.split(":");
  }

  /**
   * @return the path
   */
  public String[] getPath() {
    return path;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < path.length; i++) {
      if (i > 0) {
        sb.append(":");
      }
      sb.append(path[i]);
    }
    return sb.toString();
  }
}
