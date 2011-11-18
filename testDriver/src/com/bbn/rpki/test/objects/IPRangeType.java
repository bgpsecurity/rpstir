package com.bbn.rpki.test.objects;

/**
 * Enumerate the types of ranges used
 *
 * @author tomlinso
 */
public enum IPRangeType {
  ipv4(4, 32),
  ipv6(4, 128),
  as(0, 32);
  private int intValue;
  private int bits;
  IPRangeType(int intValue, int bits) {
    this.intValue = intValue;
    this.bits = bits;
  }
  /**
   * @return the width of the address in bits
   */
  public int getBits() {
    return bits;
  }
  
  public int getIntValue() {
    return intValue;
  }
}