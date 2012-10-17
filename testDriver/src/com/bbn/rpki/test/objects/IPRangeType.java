package com.bbn.rpki.test.objects;

import java.math.BigInteger;

/**
 * Enumerate the types of ranges used
 *
 * @author tomlinso
 */
public enum IPRangeType implements Constants {
  /** ipv6 address range */
  ipv4(32),

  /** ipv4 address range */
  ipv6(128),

  /** as range */
  as(32);


  private final int bits;
  private final BigInteger max;

  /**
   * @return the max
   */
  public BigInteger getMax() {
    return max;
  }

  IPRangeType(int bits) {
    this.bits = bits;
    this.max = TWO.pow(bits).subtract(ONE);
  }

  /**
   * @return the width of the address in bits
   */
  public int getBits() {
    return bits;
  }
}