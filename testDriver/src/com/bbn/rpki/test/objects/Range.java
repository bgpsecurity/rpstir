/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

/**
 * Represents a range of IP addresses
 *
 * @author RTomlinson
 */
public class Range implements Constants, Comparable<Range> {
  
  public enum Type {
    /** UNSET */
    UNSET,
    /** RANGE */
    RANGE,
    /** PREFIX */
    PREFIX
  }
  
  /**
   * @param base
   * @param bits
   * @param version 
   * @return A Range representing the specified prefix.
   */
  public static Range createPrefix(String base, int bits, IPRangeType version) {
    BigInteger min = stringToBigInteger(base);
    BigInteger max = min.add(TWO.pow(version.getBits() - bits).subtract(BigInteger.ONE));
    assert min.and(max).equals(ZERO);
    Range range = new Range(min, max, version, false);
    return range;
  }

  /**
   * @param min_s
   * @param max_s
   * @param version
   * @return A Range spanning the given values
   */
  public static Range createRange(String min_s, String max_s, IPRangeType version) {
    BigInteger min = stringToBigInteger(min_s);
    BigInteger max = stringToBigInteger(max_s);
    Range range = new Range(min, max, version, true);
    return range;
  }

  /**
   * @param s
   * @return
   */
  private static BigInteger stringToBigInteger(String s) {
    int radix = 10;
    if (s.toLowerCase().startsWith("0x")) {
      radix = 16;
      s = s.substring(2);
    }
    return new BigInteger(s, radix);
  }
  
  IPRangeType version;
  BigInteger min;
  BigInteger max;
  private final boolean range;;
  
  /**
   * @param min
   * @param max
   * @param version 
   */
  public Range(BigInteger min, BigInteger max, IPRangeType version, boolean range) {
    super();
    this.version = version;
    this.min = min;
    this.max = max;
    this.range = range;
  }

  /**
   * @see java.lang.Comparable#compareTo(java.lang.Object)
   */
  @Override
  public int compareTo(Range o) {
    int diff = min.subtract(o.min).signum();
    if (diff != 0) return diff;
    return max.subtract(o.max).signum();
  }

  /**
   * @param b
   * @return true if b is with this
   */
  public boolean contains(Range b) {
    if (b.min.compareTo(min) < 0 || b.max.compareTo(max) > 0) return false;
    return true;
  }
  
  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    if (isPrefix() && version != IPRangeType.as) {
      BigInteger sizem1 = max.subtract(min);
      int pow = sizem1.add(BigInteger.ONE).getLowestSetBit();
      int bits = version.getBits() - pow;
      switch (version) {
      case ipv6:
        appendIPv6(sb, min);
        break;
      case ipv4:
        appendIPv4(sb, min);
        break;
      case as:
        // Should not happen
        appendAS(sb, min);
        break;
      }
      sb.append("/").append(bits);
    } else {
      // is range
      switch (version) {
      case ipv6:
        appendIPv6(sb, min);
        sb.append("-");
        appendIPv6(sb, max);
        break;
      case ipv4:
        appendIPv4(sb, min);
        sb.append("-");
        appendIPv4(sb, max);
        break;
      case as:
        appendAS(sb, min);
        sb.append("-");
        appendAS(sb, max);
        break;
      }
    }
    return sb.toString();
  }

  /**
   * @param sb
   * @param q 
   * @return
   */
  private StringBuilder appendAS(StringBuilder sb, BigInteger q) {
    return sb.append(q);
  }

  /**
   * @param sb
   * @param q
   */
  private void appendIPv6(StringBuilder sb, BigInteger q) {
    boolean skipping = false;
    boolean skipped = false;
    for (int shift = 128 - 16; shift >= 0; shift -= 16) {
      int x = q.shiftRight(shift).and(SXTN_BIT_MASK).intValue();
      if (x == 0) {
        if (skipping) continue;
        if (!skipped) {
          // Start skipping zeros
          sb.append(":");
          skipping = true;
          continue;
        }
      } else {
        if (skipping) {
          skipped = true;
          skipping = false;
        }
      }
      sb.append(":").append(String.format("%04X", x));
    }
    if (skipping) sb.append(":");
  }
  
  private void appendIPv4(StringBuilder sb, BigInteger q) {
    int i = q.intValue();
    for (int shift = 24; shift >= 0; shift -= 8) {
      int b = (i >> shift) & 0xff;
      if (shift < 24) sb.append(".");
      sb.append(b);
    }
  }

  /**
   * A prefix is a range with a size that is a power of two and for which
   * the min address is a multiple of the size.
   * @return true if this is a prefix
   */
  public boolean couldBePrefix() {
    BigInteger sizem1 = max.subtract(min);
    if (isPowerOfTwo(sizem1.add(BigInteger.ONE))) {
      return min.and(sizem1).equals(BigInteger.ZERO);
    }
    return false;
  }
  
  /**
   * @return true if this Range is being used as a prefix
   */
  public boolean isPrefix() {
    return !range;
  }

  /**
   * @param x
   * @return true if this is a power of two
   */
  public static boolean isPowerOfTwo(BigInteger x) {
    // for a power of two, x & (x - 1) == 0
    return x.and(x.subtract(BigInteger.ONE)).equals(BigInteger.ZERO);
  }

  /**
   * @param b
   * @return true if b overlaps this Range
   */
  public boolean overlaps(Range b) {
    return min.compareTo(b.max) < 0 && max.compareTo(b.min) >= 0; 
  }
}