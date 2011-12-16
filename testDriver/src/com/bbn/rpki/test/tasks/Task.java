/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

/**
 * The interface for all tasks
 *
 * @author tomlinso
 */
public abstract class Task {
  
  private Task successTest;
  
  /**
   * @return the successTest
   */
  public Task getSuccessTest() {
    return successTest;
  }

  /**
   * @param successTest the successTest to set
   */
  public void setSuccessTest(Task successTest) {
    this.successTest = successTest;
  }

  /**
   * Runs the task
   */
  public abstract void run();
  
  /**
   * @return the number of different breakdown options available
   */
  public abstract int getBreakdownCount();
  
  /**
   * @param n
   * @return the specified TaskBreakdown
   */
  public abstract TaskBreakdown getTaskBreakdown(int n);
  
  protected abstract String getLogDetail();
  
  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public final String toString() { 
    String logDetail = getLogDetail();
    return getClass().getSimpleName() + (logDetail == null ? "" : " " + logDetail);
  }  
}
