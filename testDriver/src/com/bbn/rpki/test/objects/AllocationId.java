/*
 * Created on Oct 22, 2012
 */
package com.bbn.rpki.test.objects;

import java.util.HashMap;
import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class AllocationId implements Comparable<AllocationId> {

  private static Map<String, AllocationId> usedIds = new HashMap<String, AllocationId>();

  /**
   * @param string
   * @return a unique id string
   */
  public static AllocationId get(String string) {
    String t = string;
    int suffix = 0;
    while (usedIds.containsKey(t)) {
      t = string + "-" + ++suffix;
    }
    AllocationId allocationId = new AllocationId(t);
    usedIds.put(t, allocationId);
    return allocationId;
  }

  public static void test(String id) {
    if (usedIds.containsKey(id)) {
      return;
    }
    throw new RuntimeException("Allocation id not allocated by AllocationId");
  }

  /**
   * @return a generated allocation id
   */
  public static AllocationId generate() {
    return get("alloc");
  }

  private final String name;

  /**
   * @param t
   */
  public AllocationId(String t) {
    this.name = t;
  }

  @Override
  public int compareTo(AllocationId o) {
    return name.compareTo(o.name);
  }

  /**
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    return result;
  }

  /**
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AllocationId other = (AllocationId) obj;
    if (name == null) {
      if (other.name != null) {
        return false;
      }
    } else if (!name.equals(other.name)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return name;
  }
}
