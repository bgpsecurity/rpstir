/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

/**
 * Interface and support for all actions
 *
 * @author tomlinso
 */
public abstract class AbstractAction {

  protected static final String ATTR_TYPE = "type";

  protected static final String ATTR_ALLOCATION_ID = "allocationId";

  protected static final String ATTR_ALLOCATION_INDEX = "allocationIndex";

  protected static final String ATTR_PARENT_COMMON_NAME = "parentCommonName";

  protected static final String ATTR_COMMON_NAME = "commonName";
  
  /**
   * Perform the action
   */
  public abstract void execute();
}
