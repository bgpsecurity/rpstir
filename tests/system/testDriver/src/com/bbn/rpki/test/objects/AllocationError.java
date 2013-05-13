/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class AllocationError extends RuntimeException {

  /**
   * @param string
   */
  public AllocationError(String string) {
    super(string);
  }

}
