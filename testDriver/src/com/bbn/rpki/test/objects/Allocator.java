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
      if (DEBUG_ON) System.out.println("IPv4 Request: " + iplist);
      
      //  Note that the following may raise an exception!
      IPRangeList allocated_pairs =
          RangeAllocator.allocate(this.ipv4ResourcesFree,
                                         iplist,
                                         true);
      
      allocated_pairs.sort();
      return allocated_pairs;
  }

  protected IPRangeList subAllocateIPv6(List<Pair> iplist) {
    if (DEBUG_ON) System.out.println("IPv6 Request: " + iplist);
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
        RangeAllocator.allocate(this.ipv6ResourcesFree,
                                iplist,
                                true);
  
    //  FIXME: maxlength not supported
    allocated_pairs.sort();
    return allocated_pairs;
  }

  protected IPRangeList subAllocateAS(List<Pair> asList) {
    if (DEBUG_ON) System.out.println("AS Request: " + asList);
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
        RangeAllocator.allocate(this.asResourcesFree,
                                asList,
                                false);
    allocated_pairs.sort();
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
    RangeAllocator.removeRange(resourcesFree, range);
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
    RangeAllocator.addRange(resourcesFree, range);
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
