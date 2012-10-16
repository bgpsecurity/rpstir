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
    // TODO need a better key incorporating the parent
    if (allocationId == null) {
      return;
    }
    System.out.println("RecordAllocation " + allocationId + ": " + list);
    IPRangeType rangeType = list.getIpVersion();
    Map<String, IPRangeList> selectMap = selectMap(rangeType);
    IPRangeList ranges = selectMap.get(allocationId);
    if (ranges == null) {
      ranges = new IPRangeList(rangeType);
      selectMap(rangeType).put(allocationId, ranges);
    }
    ranges.addAll(list);
  }

  /**
   * @param ipVersion
   * @return Map from allocationId to ranges for the specified INR type
   */
  public Map<String, IPRangeList> selectMap(IPRangeType ipVersion) {
    Map<String, IPRangeList> map;
    switch (ipVersion) {
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
      map = null;
    }
    return map;
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

  /**
   * @param parent
   * @param ca_Object
   * @param rangeType
   * @param allocationId
   * @return the allocation range list corresponding to the allocationid.
   */
  public IPRangeList findAllocation(CA_Object parent, CA_Object ca_Object, IPRangeType rangeType, String allocationId) {
    return selectMap(rangeType).get(allocationId);
  }
}
