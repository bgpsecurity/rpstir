/*
 * Created on Oct 18, 2012
 */
package com.bbn.rpki.test.objects;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class Clock {

  private Clock() {
    //empty
  }

  public static long now() {
    return System.currentTimeMillis();
  }
}
