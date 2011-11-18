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
public class Allocator extends CA_Obj {

  protected IPRangeList ipv4ResourcesFree;
  protected IPRangeList ipv6ResourcesFree;
  protected IPRangeList asResourcesFree;
  protected IPRangeList ipv4Resources;
  protected IPRangeList ipv6Resources;
  protected IPRangeList asResources;

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

}
