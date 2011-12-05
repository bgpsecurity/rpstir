package com.bbn.rpki.test.objects;

/**
 * Enumerate the types of ranges used
 *
 * @author tomlinso
 */
public enum IPRangeType {
  /** ipv6 address range */
  ipv4(32),

  /** ipv4 address range */
  ipv6(128),

  /** as range */
  as(32);
  
 
  private int bits;
  
  IPRangeType(int bits) {
    this.bits = bits;
  }
  
  /**
   * @return the width of the address in bits
   */
  public int getBits() {
    return bits;
  }
}