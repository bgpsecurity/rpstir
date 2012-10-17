/*
 * Created on Oct 16, 2012
 */
package com.bbn.rpki.test.objects;

import java.util.ArrayList;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class TypedPairList extends ArrayList<TypedPair> {

  /**
   * @param type
   * @return
   */
  public List<Pair> extract(IPRangeType type) {
    List<Pair> ret = new ArrayList<Pair>();
    for (TypedPair pair : this) {
      if (pair.type == type) {
        ret.add(pair);
      }
    }
    return ret;
  }
}
