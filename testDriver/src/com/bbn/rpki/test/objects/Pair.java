/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Pair {
  public String tag;
  public BigInteger arg;
  
  public Pair(String tag, BigInteger arg) {
    this.tag = tag;
    this.arg = arg;
  }
  
  @Override
  public String toString() {
    return String.format("%s%%%d", tag, arg);
  }
}
