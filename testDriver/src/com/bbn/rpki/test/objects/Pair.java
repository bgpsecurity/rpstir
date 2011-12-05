/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

/**
 * Represents values with a text tag and a numeric value
 *
 * @author RTomlinson
 */
public class Pair {
  /** The text tag of the value */
  public String tag;
  
  /** The numeric part of the value */
  public BigInteger arg;
  
  /**
   * @param tag
   * @param arg
   */
  public Pair(String tag, BigInteger arg) {
    this.tag = tag;
    this.arg = arg;
  }
  
  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("%s%%%d", tag, arg);
  }
}
