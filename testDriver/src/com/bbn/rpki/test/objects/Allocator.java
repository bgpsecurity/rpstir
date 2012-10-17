/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;

/**
 * Keeps track of the allocations for an entity (e.g. CA)
 * 
 * Maintains two lists for each of three types of numbers (as, ipv4, ipv6).
 * The "free" lists show the currently available numbers that can be allocated from this entity.
 * The "allocated" lists show the total allocates received by this entity.
 * 
 * Ranges can be added in two ways representing either the receipt of a new allocation from another
 * entity or the return of a previous allocation to another entity. The former adds the ranges to
 * both lists while the latter only adds to the free list. Similarly, ranges can be removed in two
 * ways representing the cancellation of a previous allocation from another entity or the allocation
 * of ranges to another entity. The latter affects the free list. the former is more complex.
 * 
 * Normally, if we lose our allocation, allocations from us to another must also cancelled. In a
 * perfect world, we would already have cancelled the suballocations. Not having a perfect world at
 * our disposal, we simply remove from both lists, if present and when the suballocation is
 * cancelled, we do not add anything that is not in the allocated list back to the free list.
 *
 * @author RTomlinson
 */
public abstract class Allocator implements Constants {
  private static class ResourcePair {
    IPRangeList free;
    IPRangeList rcvd;
    ResourcePair(IPRangeType rangeType) {
      free = new IPRangeList(rangeType);
      rcvd = new IPRangeList(rangeType);
    }
  }
  private final ResourcePair asResources = new ResourcePair(IPRangeType.as);
  private final ResourcePair ipv4Resources = new ResourcePair(IPRangeType.ipv4);
  private final ResourcePair ipv6Resources = new ResourcePair(IPRangeType.ipv6);
  protected boolean modified = true;

  protected IPRangeList subAllocateIPv4(List<? extends Pair> iplist) {
    if (DEBUG_ON) {
      System.out.println("IPv4 Request: " + iplist);
    }

    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
        this.ipv4Resources.free.allocate(iplist, true);

    return allocated_pairs;
  }

  protected IPRangeList subAllocateIPv6(List<? extends Pair> iplist) {
    if (DEBUG_ON) {
      System.out.println("IPv6 Request: " + iplist);
    }
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
        this.ipv6Resources.free.allocate(iplist, true);

    return allocated_pairs;
  }

  protected IPRangeList subAllocateAS(List<? extends Pair> asList) {
    if (DEBUG_ON) {
      System.out.println("AS Request: " + asList);
    }
    //  Note that the following may raise an exception!
    IPRangeList allocated_pairs =
        this.asResources.free.allocate(asList, false);
    return allocated_pairs;
  }

  protected void addRcvdRanges(IPRangeList rangeList) {
    ResourcePair resources = selectResources(rangeList.getIpVersion());
    resources.rcvd.addAll(rangeList);
    resources.free.addAll(rangeList);
  }

  /**
   * Represents a cancellation of allocation to this allocator.
   * Remove from rcvd list and remove what we can from free list
   * 
   * @param rangeType
   * @param range
   */
  public void removeRcvdRanges(IPRangeList rangeList) {
    ResourcePair resources = selectResources(rangeList.getIpVersion());
    resources.rcvd.removeAll(rangeList);
    resources.free.removeAll(rangeList.intersection(resources.free));
  }

  protected void removeRcvdRange(Range range) {
    ResourcePair resources = selectResources(range.version);
    resources.rcvd.remove(range);
  }

  private ResourcePair selectResources(IPRangeType rangeType) {
    ResourcePair resources;
    switch (rangeType) {
    case ipv4:
      resources = ipv4Resources;
      break;
    case ipv6:
      resources = ipv6Resources;
      break;
    case as:
      resources = asResources;
      break;
    default:
      resources = null;
    }
    assert resources != null;
    return resources;
  }

  /**
   * Represents the return of a suballocation
   * 
   * @param rangeType
   * @param range
   */
  protected void addFreeRanges(IPRangeList rangeList) {
    ResourcePair resources = selectResources(rangeList.getIpVersion());
    IPRangeList intersection = resources.rcvd.intersection(rangeList);
    resources.free.addAll(intersection);
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

  /**
   * @param rangeType
   * @return
   */
  protected IPRangeList getRcvdRanges(IPRangeType rangeType) {
    return selectResources(rangeType).rcvd;
  }

  /**
   * @param rangeType
   * @return
   */
  protected IPRangeList getFreeRanges(IPRangeType rangeType) {
    return selectResources(rangeType).free;
  }
}
