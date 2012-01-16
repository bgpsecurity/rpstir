/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public abstract class Allocator implements Constants {

  protected IPRangeList ipv4ResourcesFree;
  protected IPRangeList ipv6ResourcesFree;
  protected IPRangeList asResourcesFree;
  protected IPRangeList ipv4Resources = new IPRangeList(IPRangeType.ipv4);
  protected IPRangeList ipv6Resources = new IPRangeList(IPRangeType.ipv6);
  protected IPRangeList asResources = new IPRangeList(IPRangeType.as);
  protected boolean modified = true;

  protected IPRangeList subAllocateIPv4(List<Pair> iplist) {
    if (DEBUG_ON) {
      System.out.println("IPv4 Request: " + iplist);
    }

    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
      this.ipv4ResourcesFree.allocate(iplist, true);

    return allocated_pairs;
  }

  protected IPRangeList subAllocateIPv6(List<Pair> iplist) {
    if (DEBUG_ON) {
      System.out.println("IPv6 Request: " + iplist);
    }
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
      this.ipv6ResourcesFree.allocate(iplist, true);

    //  FIXME: maxlength not supported
    return allocated_pairs;
  }

  protected IPRangeList subAllocateAS(List<Pair> asList) {
    if (DEBUG_ON) {
      System.out.println("AS Request: " + asList);
    }
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
      this.asResourcesFree.allocate(asList, false);
    return allocated_pairs;
  }


  /**
   * @param rangeType
   * @param range
   */
  public void removeRange(IPRangeType rangeType, Range range) {
    IPRangeList resourcesFree;
    switch (rangeType) {
    case ipv4:
      resourcesFree = ipv4ResourcesFree;
      break;
    case ipv6:
      resourcesFree = ipv6ResourcesFree;
      break;
    case as:
      resourcesFree = asResourcesFree;
      break;
    default:
      return;
    }
    resourcesFree.remove(range);
  }

  /**
   * @param rangeType
   * @param range
   */
  public void addRange(IPRangeType rangeType, Range range) {
    IPRangeList resourcesFree;
    switch (rangeType) {
    case ipv4:
      resourcesFree = ipv4ResourcesFree;
      break;
    case ipv6:
      resourcesFree = ipv6ResourcesFree;
      break;
    case as:
      resourcesFree = asResourcesFree;
      break;
    default:
      return;
    }
    resourcesFree.add(range);
  }

  /**
   * @return the modified
   */
  public boolean isModified() {
    return modified;
  }

  /**
   * @param modified the modified to set
   */
  public void setModified(boolean modified) {
    this.modified = modified;
  }
}
