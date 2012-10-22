/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Holds a list of ranges representing an allocation, free list, etc.
 *
 * @author RTomlinson
 */
public class IPRangeList implements Iterable<Range>, Constants {
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

  public static void main(String...args) {
    IPRangeList rcvd = new IPRangeList(IPRangeType.as);
    Range range1 = new Range(new BigInteger("1000"), new BigInteger("1999"), IPRangeType.as, true);
    Range range2 = new Range(new BigInteger("2000"), new BigInteger("2999"), IPRangeType.as, true);
    rcvd.add(range1);
    rcvd.add(range2);
    IPRangeList free = new IPRangeList(rcvd);
    // Allocate a prefix that must start at 1024 cutting a hole
    IPRangeList suballoc = free.allocate(Collections.singletonList(new Pair("p", 1024)), true);
    // Rescind the first allocation
    rcvd.remove(range1);
    free.removeAll(new IPRangeList(range1).intersection(free));
    IPRangeList intersection = rcvd.intersection(suballoc);
    System.out.println("rcvd = " + rcvd);
    System.out.println("free = " + free);
    System.out.println("suballoc = " + suballoc);
    System.out.println("intersection = " + intersection);
    free.addAll(intersection);
    System.out.println("rcvd = " + rcvd);
    System.out.println("free = " + free);
    System.out.println("suballoc = " + suballoc);
    System.out.println("intersection = " + intersection);
  }

  private final IPRangeType ipVersion;
  private final List<Range> rangeList;

  /**
   * @param ipVersion
   */
  public IPRangeList(IPRangeType ipVersion) {
    this.rangeList = new ArrayList<Range>();
    this.ipVersion = ipVersion;
  }

  /**
   * Copy constructor
   * 
   * @param orig
   */
  public IPRangeList(IPRangeList orig) {
    rangeList = new ArrayList<Range>(orig.rangeList);
    this.ipVersion = orig.ipVersion;
  }

  /**
   * @param ranges
   */
  public IPRangeList(Range...ranges) {
    this(ranges[0].version);
    for (Range range : ranges) {
      add(range);
    }
  }

  /**
   * @param size
   * @param version
   */
  public IPRangeList(int size, IPRangeType version) {
    rangeList = new ArrayList<Range>(size);
    this.ipVersion = version;
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
    StringBuilder sb = new StringBuilder(getIpVersion().name());
    sb.append(": ");
    boolean first = true;
    for (Range range : this) {
      if (first) {
        first = false;
      } else {
        sb.append(",");
      }
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

  /**
   * Allocate Internet number resources based on a free list.

    Inputs:

    free_list - [list of integer pairs] blocks of unallocated
                resources, e.g. [(3,10), (13,17), ...]

    used_list - [list of integer pairs] blocks of allocated resources,
                e.g. [(11,12), (18,34), ...]

    requests - [list of character/integer pairs] requests for resources,
                where each request block is denoted by a pair (reqtype,
                amount).  The "reqtype" field must be either 'p' (IP
                prefix) or 'r' (IP/AS range).  The "amount" field must
                be a positive integer specifying the number of
                Internet resource numbers to allocate (i.e. IP
                addresses, or AS numbers).  If "reqtype" is 'p', then
                "amount" must be a power of 2. e.g. [('r',5), ('p',
                256), ('r', 16), ...]

    range_not_prefix - [boolean] If set to True (default), returned
                ranges must NOT be expressible as a prefix.  This
                option should be set to True for IPv4/IPv6 allocation,
                and False for AS number allocation.  The default
                behavior conforms to RFC 3779 encoding requirements
                that ranges equivalent to prefixes MUST be expressed
                as prefixes.  Therefore, a "range" request must not
                return a prefix.

    Returns:

    allocated_blocks - [list of integer pairs] blocks allocated to the
                child, corresponding to the order of requests.  Note
                that the blocks MAY NOT be in ascending order of
                resource number.

    Side effects:

    The free_list and used_list will be updated to reflect the blocks
    allocated to the child.

    Exceptions:

    AllocationError - If the request cannot be fulfilled, the function
    raises an AllocationError exception.

   * @param requests
   * @param expressAsRange
   * @return the allocated ranges
   */
  public IPRangeList allocate(List<? extends Pair> requests,
                              boolean expressAsRange) {
    IPRangeList ret = new IPRangeList(ipVersion);

    for (Pair request : requests) {
      char reqType = request.tag.charAt(0);
      BigInteger reqSize = request.arg;
      Range issuedBlock;
      if (reqType == 'r') {
        issuedBlock = allocateSingleRange(reqSize, ret, expressAsRange);
      } else if (reqType == 'p') {
        issuedBlock = allocateSinglePrefix(reqSize, ret, expressAsRange);
      } else {
        throw new AllocationError("Invalid requestType: " + reqType);
      }
      ret.rangeList.add(issuedBlock);
    }
    return ret;
  }

  /**
   * @param rangeList
   * @param reqSize
   * @param expressAsRange
   * @return
   */
  private Range allocateSinglePrefix(BigInteger reqSize, IPRangeList allocatedList, boolean expressAsRange) {
    if (!Range.isPowerOfTwo(reqSize)) {
      throw new AllocationError("Illegal prefix size: " + reqSize);
    }
    for (int i = 0, n = rangeList.size(); i < n; i++) {
      Range x = firstFitPrefix(rangeList.get(i), allocatedList, reqSize, expressAsRange);
      if (x != null) {
        removeRange(i, x);
        return x;
      }
    }
    throw new AllocationError("Unable to fulfill request for prefix of size " + reqSize);
  }

  /**
   * @param rangeList
   * @param i
   * @param x
   */
  private void removeRange(int i, Range x) {
    List<Range> perforated = perforate(rangeList.get(i), x);
    List<Range> insertion = rangeList.subList(i, i + 1);
    insertion.clear();
    insertion.addAll(perforated);
  }

  /**
   * @param rangeList
   * @param reqSize
   * @return
   */
  private Range allocateSingleRange(BigInteger reqSize,
                                    IPRangeList allocatedBlocks, boolean expressAsRange) {
    for (int i = 0, n = rangeList.size(); i < n; i++) {
      Range firstRange = rangeList.get(i);
      Range x = firstFitRange(firstRange, reqSize, allocatedBlocks, expressAsRange);
      if (x != null) {
        List<Range> perforated = perforate(firstRange, x);
        List<Range> insertion = rangeList.subList(i,  i + 1);
        insertion.clear();
        insertion.addAll(perforated);
        return x;
      }
    }
    throw new AllocationError("Unable to fulfill request for range of size " + reqSize);
  }

  /**
   * Remove b from the enclosing range a
   * @param a
   * @param b
   * @return the resulting elements
   */
  private List<Range> perforate(Range a, Range b) {
    if (!a.contains(b)) {
      throw new AllocationError("Cannot perforate " + b + " from " + a);
    }
    List<Range> ret = new ArrayList<Range>(2);
    if (a.min.compareTo(b.min) < 0) {
      ret.add(new Range(a.min, b.min.subtract(ONE), ipVersion, true));
    }
    if (a.max.compareTo(b.max) > 0) {
      ret.add(new Range(b.max.add(ONE), a.max, ipVersion, true));
    }
    return ret;
  }

  /**
   * @param reqSize
   * @return
   */
  private Range firstFitPrefix(Range free_block, IPRangeList allocated_blocks,
                               BigInteger amount, boolean expressAsRange) {
    BigInteger search_position = free_block.min;
    while (true) {
      Range candidate = next_prefix(search_position, amount, allocated_blocks.getIpVersion(), expressAsRange);
      if (!free_block.contains(candidate)) {
        // out of resources
        break;
      }
      Range conflict = detectConflict(candidate, allocated_blocks);
      if (conflict == null) {
        return candidate;
      }
      // not overlapping or adjacent
      search_position = conflict.max.add(TWO);
    }
    return null;
  }

  private Range next_prefix(BigInteger start_pos, BigInteger amount, IPRangeType version, boolean expressAsRange) {
    // Return the next prefix of the requested size.

    if (!Range.isPowerOfTwo(amount)) {
      throw new AllocationError(String.format("Prefix request has invalid size: %d.", amount));
    }
    BigInteger next_multiple;
    if (start_pos.mod(amount).equals(BigInteger.ZERO)) {
      next_multiple = start_pos;
    } else {
      next_multiple = start_pos.divide(amount).add(BigInteger.ONE).multiply(amount);
    }
    Range prefix = new Range(next_multiple,
                             next_multiple.add(amount).subtract(BigInteger.ONE),
                             version, expressAsRange);
    if (!prefix.couldBePrefix()) {
      throw new RuntimeException(prefix + " should have been a prefix");
    }
    return prefix;
  }

  /**
   * @param reqSize
   * @return
   */
  private Range firstFitRange(Range freeRange, BigInteger reqSize, IPRangeList allocatedBlocks, boolean expressAsRange) {
    BigInteger searchPosition = freeRange.min;
    while (true) {
      Range candidate = new Range(searchPosition, searchPosition.add(reqSize).subtract(BigInteger.ONE), freeRange.version, expressAsRange);
      if (!freeRange.contains(candidate)) {
        return null;
      }
      if (expressAsRange && candidate.couldBePrefix()) {
        searchPosition = searchPosition.add(BigInteger.ONE);
        continue;
      }
      Range conflict = detectConflict(candidate, allocatedBlocks);
      if (conflict == null) {
        return candidate;
      }
      searchPosition = conflict.max.add(TWO);
    }
  }

  /**
   * @param candidate
   * @param allocatedBlocks
   * @return
   */
  private static Range detectConflict(Range candidate, IPRangeList allocatedBlocks) {
    /*Detect a resource overlap or adjacency conflict.

    Return an element (integer pair) from allocated_blocks (list of
    integer pairs) that conflicts with candidate_block (integer pair).
    An element can conflict by being numerically adjacent to the
    candidate, or by numerically overlapping with it.  If no element
    of allocated_blocks conflicts with candidate_block, return None.

    >>> detect_conflict((1,3), []) # no allocated blocks, no conflict
    >>> detect_conflict((1,3), [(7,9)]) # no conflict
    >>> detect_conflict((1,3), [(7,9), (4,5)])
    (4, 5)
     */
    Range expanded = new Range(candidate.min.subtract(BigInteger.ONE),
                               candidate.max.add(BigInteger.ONE),
                               candidate.version, true);
    for (Range a : allocatedBlocks) {
      if (a.overlaps(expanded)) {
        return a;
      }
    }
    return null;
  }

  /**
   * @param range
   */
  public void add(Range range) {
    for (int i = 0, n = rangeList.size(); i <= n; i++) {
      Range test = i < n ? rangeList.get(i) : null;
      Range test2 = null;
      if (test == null || test.compareTo(range) > 0) {
        assert test == null || !test.overlaps(range);
        // There are four legal cases:
        //  range is adjacent to test
        //  range is adjacent to the preceding range
        //  range is adjacent to neither
        //  range is adjacent to both
        int x = 0;
        if (test != null) {
          if (range.max.equals(test.min.subtract(BigInteger.ONE))) {
            // Adjacent to test
            x |= 1;
          }
        }
        if (i > 0) {
          // May be adjacent to the preceding range
          test2 = rangeList.get(i - 1);
          assert !test2.overlaps(range);
          if (range.min.equals(test2.max.add(BigInteger.ONE))) {
            x |= 2;
          }
        }
        switch (x) {
        case 0:
          // Not adjacent at all
          rangeList.add(i, range);
          return;
        case 1:
          // Adjacent to following range
          rangeList.set(i, new Range(range.min, test.max, test.version, false));
          return;
        case 2:
          // Adjacent to preceding range
          rangeList.set(i - 1, new Range(test2.min, range.max, test2.version, false));
          return;
        case 3:
          // adjacent to both
          rangeList.set(i - 1, new Range(test2.min, test.max, test.version, false));
          rangeList.remove(i);
          return;
        }
        return;
      }
    }
    rangeList.add(range);
  }

  /**
   * Remove as much as possible of the given range
   * Remember the invariants are that every range is separate from other ranges
   * so that range must fall entirely within one range in the list.
   * @param range
   * @return true if the range was successfully removed
   */
  public boolean remove(Range range) {
    if (range == null) {
      return true;
    }
    for (int i = 0, n = rangeList.size(); i < n; i++) {
      Range test = rangeList.get(i);
      if (test.min.compareTo(range.max) > 0) {
        // Never found an intersection
        return false;
      }
      if (test.max.compareTo(range.min) < 0) {
        // Still looking
        continue;
      }
      if (!test.contains(range)) {
        // Error -- trying to remove a range that is not completely present.
        return false;
      }
      // Removing range can leave behing 0, 1, or two pieces
      List<Range> left = perforate(test, range);
      // The sublist containing test
      List<Range> sub = rangeList.subList(i, i + 1);
      // Replace the sublist with what is left of it.
      sub.clear();
      sub.addAll(left);
      return true;
    }
    return false;
  }

  /**
   * Test if this range list contains the given range.
   * Remember the invariants are that every range is separate from other ranges
   * so that range must fall entirely within one range in the list.
   * @param range
   * @return true if range is contained within the rangeList
   */
  public boolean contains(Range range) {
    for (int i = 0, n = rangeList.size(); i < n; i++) {
      Range test = rangeList.get(i);
      if (test.min.compareTo(range.max) > 0) {
        // Never found an overlap
        return false;
      }
      if (test.max.compareTo(range.min) < 0) {
        // Still looking
        continue;
      }
      return test.contains(range);
    }
    return false;
  }

  /**
   * Computes the intersection between this RangeList and another
   * 
   * @param rangeList
   * @return the intersection or null if the lists do not intersect
   */
  public IPRangeList intersection(IPRangeList rangeList) {
    IPRangeList ret = new IPRangeList(ipVersion);
    for (Range range : rangeList) {
      for (Range testRange : this) {
        Range intersection = range.intersection(testRange);
        if (intersection != null) {
          ret.add(intersection);
        }
      }
    }
    return ret;
  }

  /**
   * @param rangeList
   * @return true if the entire rangeList is contained within this
   */
  public boolean containsAll(IPRangeList rangeList) {
    for (Range range : rangeList) {
      if (!contains(range)) {
        return false;
      }
    }
    return true;
  }

  /**
   * @param rangeList
   * @return true if the entire rangeList could be removed
   */
  public boolean removeAll(IPRangeList rangeList) {
    if (rangeList == this) {
      this.rangeList.clear();
      return true;
    }
    for (Range range : rangeList) {
      if (!contains(range)) {
        return false;
      }
    }
    for (Range range : rangeList) {
      remove(range);
    }
    return true;
  }

  /**
   * @param allocation
   */
  public void addAll(IPRangeList allocation) {
    for (Range range : allocation) {
      add(range);
    }
  }

  /**
   * @param allocationIndex
   * @return the Range at the specified index
   */
  public Range get(int allocationIndex) {
    return rangeList.get(allocationIndex);
  }

  /**
   * @see java.lang.Iterable#iterator()
   */
  @Override
  public Iterator<Range> iterator() {
    return Collections.unmodifiableList(rangeList).iterator();
  }

  /**
   * @return true if no ranges are present
   */
  public boolean isEmpty() {
    return rangeList.isEmpty();
  }
}
