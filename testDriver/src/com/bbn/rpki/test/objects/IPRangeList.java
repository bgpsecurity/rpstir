/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Holds a list of ranges representing an allocation, free list, etc.
 *
 * @author RTomlinson
 */
public class IPRangeList extends ArrayList<Range> {
  /** Indicates the address range is inherited */
  public static final IPRangeList IPV4_INHERIT = new IPRangeList(IPRangeType.ipv4);
  
  /** Indicates the address range is inherited */
  public static final IPRangeList IPV6_INHERIT = new IPRangeList(IPRangeType.ipv6);
  
  /** Indicates the address range is inherited */
  public static final IPRangeList AS_INHERIT = new IPRangeList(IPRangeType.as);
  
  /** Predefined constants for an empty range */
  public static final IPRangeList IPV4_EMPTY = new IPRangeList(IPRangeType.ipv4);
  
  /** Predefined constants for an empty range */
  public static final IPRangeList IPV6_EMPTY = new IPRangeList(IPRangeType.ipv6);
  
  /** Predefined constants for an empty range */
  public static final IPRangeList AS_EMPTY = new IPRangeList(IPRangeType.as);
  
  /**
   * @param l
   * @return true if the specified list is an inherit list
   */
  public static boolean isInherit(IPRangeList l) {
    switch(l.getIpVersion()) {
    case ipv4: return l == IPV4_INHERIT;
    case ipv6: return l == IPV6_INHERIT;
    case as: return l == AS_INHERIT;
    }
    return false;
  }
        
  private final IPRangeType ipVersion;
  
  /**
   * @param ipVersion
   */
  public IPRangeList(IPRangeType ipVersion) {
    this.ipVersion = ipVersion;
  }
  
  /**
   * Copy constructor
   * 
   * @param orig
   */
  public IPRangeList(IPRangeList orig) {
    addAll(orig);
    this.ipVersion = orig.ipVersion;
  }
  
  /**
   * @param size 
   * @param version 
   */
  public IPRangeList(int size, IPRangeType version) {
    super(size);
    this.ipVersion = version;
  }

  /**
   * Sort the list
   */
  public void sort() {
    Collections.sort(this);
  }

  /**
   * @return the ipVersion
   */
  public IPRangeType getIpVersion() {
    return ipVersion;
  }
  
  /**
   * @see java.util.AbstractCollection#toString()
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (Range range : this) {
      sb.append(range);
    }
    return sb.toString();
  }

  /**
   * @param min 
   * @param max 
   */
  public void addRange(BigInteger min, BigInteger max) {
    add(new Range(min, max, ipVersion, true));
  }
}
