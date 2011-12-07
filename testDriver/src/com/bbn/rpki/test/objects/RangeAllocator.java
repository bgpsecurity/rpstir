/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.List;

/**
 * Allocator for ranges of numbers (e.g. IP addresses)
 *
 * @author RTomlinson
 */
public class RangeAllocator implements Constants {

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

   * @param freeList 
   * @param requests 
   * @param expressAsRange 
   * @return the allocated ranges
   */
  public static IPRangeList allocate(IPRangeList freeList,
                                     List<Pair> requests,
                                     boolean expressAsRange) {
    IPRangeList ret = new IPRangeList(freeList.getIpVersion());
    
    for (Pair request : requests) {
      char reqType = request.tag.charAt(0);
      BigInteger reqSize = request.arg;
      Range issuedBlock;
      if (reqType == 'r') {
        issuedBlock = allocateSingleRange(freeList, reqSize, ret, expressAsRange);
      } else if (reqType == 'p') {
        issuedBlock = allocateSinglePrefix(freeList, ret, reqSize, expressAsRange);
      } else {
        throw new AllocationError("Invalid requestType: " + reqType);
      }
      ret.add(issuedBlock);
    }
    return ret;
  }

  /**
   * @param freeList
   * @param reqSize
   * @param expressAsRange 
   * @return
   */
  private static Range allocateSinglePrefix(IPRangeList freeList, IPRangeList allocatedList, BigInteger reqSize, boolean expressAsRange) {
    if (!Range.isPowerOfTwo(reqSize))
      throw new AllocationError("Illegal prefix size: " + reqSize);
    for (int i = 0, n = freeList.size(); i < n; i++) {
      Range x = firstFitPrefix(freeList.get(i), allocatedList, reqSize, expressAsRange);
      if (x != null) {
        List<Range> perforated = perforate(freeList.get(i), x);
        List<Range> insertion = freeList.subList(i, i + 1);
        insertion.clear();
        insertion.addAll(perforated);
        return x;
      }
    }
    throw new AllocationError("Unable to fulfill request for prefix of size " + reqSize);
  }

  /**
   * @param freeList
   * @param reqSize
   * @return
   */
  private static Range allocateSingleRange(IPRangeList freeList, BigInteger reqSize, 
                                           IPRangeList allocatedBlocks, boolean expressAsRange) {
    for (int i = 0, n = freeList.size(); i < n; i++) {
      Range firstRange = freeList.get(i);
      Range x = firstFitRange(firstRange, reqSize, allocatedBlocks, expressAsRange);
      if (x != null) {
        List<Range> perforated = perforate(firstRange, x);
        List<Range> insertion = freeList.subList(i,  i + 1);
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
  private static IPRangeList perforate(Range a, Range b) {
    if (!a.contains(b)) throw new AllocationError("Cannot perforate " + b + " from " + a);
    IPRangeList ret = new IPRangeList(2, a.version);
    if (a.min.compareTo(b.min) < 0) {
      ret.addRange(a.min, b.min.subtract(ONE));
    }
    if (a.max.compareTo(b.max) > 0) {
      ret.addRange(b.max.add(ONE), a.max);
    }
    return ret;
  }

  /**
   * @param freeList
   * @param reqSize
   * @return
   */
  private static Range firstFitPrefix(Range free_block, IPRangeList allocated_blocks,
                                      BigInteger amount, boolean expressAsRange) {
    BigInteger search_position = free_block.min;
    while (true) {
      Range candidate = next_prefix(search_position, amount, allocated_blocks.getIpVersion(), expressAsRange);
      if (!free_block.contains(candidate)) {
        // out of resources
        break;
      }
      Range conflict = detect_conflict(candidate, allocated_blocks);
      if (conflict == null)
        return candidate;
      // not overlapping or adjacent
      search_position = conflict.max.add(TWO);
    }
    return null;
  }

  private static Range next_prefix(BigInteger start_pos, BigInteger amount, IPRangeType version, boolean expressAsRange) {
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
    if (!prefix.couldBePrefix())
      throw new RuntimeException(prefix + " should have been a prefix");
    return prefix;
  }

    private static Range detect_conflict(Range candidate_block, IPRangeList allocated_blocks) {
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
      Range expanded = new Range(candidate_block.min.subtract(ONE),
                                 candidate_block.max.add(ONE), 
                                 candidate_block.version, true);
      for (Range a : allocated_blocks) {
        if (a.overlaps(expanded)) {
          return a;
        }
      }
      return null;
    }

  /**
   * @param freeList
   * @param reqSize
   * @return
   */
  private static Range firstFitRange(Range freeRange, BigInteger reqSize, IPRangeList allocatedBlocks, boolean expressAsRange) {
    // TODO Auto-generated method stub
    BigInteger searchPosition = freeRange.min;
    while (true) {
      Range candidate = new Range(searchPosition, searchPosition.add(reqSize).subtract(BigInteger.ONE), freeRange.version, expressAsRange);
      if (!freeRange.contains(candidate)) return null;
      if (expressAsRange && candidate.couldBePrefix()) {
        searchPosition = searchPosition.add(BigInteger.ONE);
        continue;
      }
      Range conflict = detectConflict(candidate, allocatedBlocks);
      if (conflict == null) return candidate;
      searchPosition = conflict.max.add(TWO);
    }
  }

  /**
   * @param candidate
   * @param allocatedBlocks
   * @return
   */
  private static Range detectConflict(Range candidate, IPRangeList allocatedBlocks) {
    Range expanded = new Range(candidate.min.subtract(BigInteger.ONE),
                               candidate.max.add(BigInteger.ONE),
                               candidate.version, true);
    for (Range a : allocatedBlocks) {
      if (a.overlaps(expanded)) return a;
    }
    return null;
  }
}
