/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Map;
import java.util.TreeMap;

import com.bbn.rpki.test.objects.Allocator;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeList;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Range;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ActionManager {
  private static ActionManager singleton;
  
  /**
   * @return the singleton ActionManager instance
   */
  public static ActionManager singleton() {
    if (singleton == null) {
      singleton = new ActionManager();
    }
    return singleton;
  }
  
  private final Map<String, IPRangeList> ipv4Allocations = new TreeMap<String, IPRangeList>();
  
  private final Map<String, IPRangeList> ipv6Allocations = new TreeMap<String, IPRangeList>();
  
  private final Map<String, IPRangeList> asAllocations = new TreeMap<String, IPRangeList>();
  
  private final Map<String, CA_Object> caObjects = new TreeMap<String, CA_Object>();
  
  private ActionManager() {
    // Nothing to do here
  }

  /**
   * @param rangeType
   * @param allocationId
   * @param allocationIndex
   * @return the specified Range
   */
  public Range findAllocation(IPRangeType rangeType, String allocationId, int allocationIndex) {
    Map<String, IPRangeList> map;
    switch (rangeType) {
    case ipv4:
      map = ipv4Allocations;
      break;
    case ipv6:
      map = ipv6Allocations;
      break;
    case as:
      map = asAllocations;
      break;
      default:
        return null;
    }
    IPRangeList rangeList = map.get(allocationId);
    return rangeList.get(allocationIndex);
  }

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param list
   */
  public void recordAllocation(Allocator parent, Allocator child, String allocationId, IPRangeList list) {
    Map<String, IPRangeList> map;
    switch (list.getIpVersion()) {
    case ipv4:
      map = ipv4Allocations;
      break;
    case ipv6:
      map = ipv6Allocations;
      break;
    case as:
      map = asAllocations;
      break;
    default:
      return;
    }
    IPRangeList old = map.put(allocationId, list);
    assert old == null;
  }

  /**
   * @param ca_object
   */
  public void recordCA_Object(CA_Object ca_object) {
    caObjects.put(ca_object.commonName, ca_object);
  }

  /**
   * @param commonName
   * @return the CA_Object with the given name
   */
  public CA_Object findCA_Object(String commonName) {
    return caObjects.get(commonName);
  }
}
