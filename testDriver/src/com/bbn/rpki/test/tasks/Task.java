/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

/**
 * The interface for all tasks
 *
 * @author tomlinso
 */
public interface Task {
  /**
   * Runs the task
   * @param epochIndex specifies which epoch is wanted
   */
  void run(int epochIndex);
  
  /**
   * @param epochIndex Specifies which epoch
   * @return the number of different breakdown options available
   */
  int getBreakdownCount(int epochIndex);
  
  /**
   * @param epochIndex Specifies which epoch
   * @param n
   * @return the specified TaskBreakdown
   */
  TaskBreakdown getTaskBreakdown(int epochIndex, int n);
  
}
