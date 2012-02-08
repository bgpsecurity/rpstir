/*
 * Created on Feb 6, 2012
 */
package com.bbn.rpki.test.tasks;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public abstract class Breakdown {
  private final String breakdownName;

  /**
   * @param breakdownName
   */
  protected Breakdown(String breakdownName) {
    super();
    this.breakdownName = breakdownName;
  }

  /**
   * @return the breakdownName
   */
  public String getBreakdownName() {
    return breakdownName;
  }

  /**
   * @param task
   * @return the TaskBreakdown created by this Breakdown for the specified task
   */
  public abstract TaskBreakdown getTaskBreakdown(TaskFactory.Task task);

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public final String toString() {
    return breakdownName;
  }
}
