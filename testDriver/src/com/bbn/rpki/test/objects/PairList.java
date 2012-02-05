/*
 * Created on Feb 3, 2012
 */
package com.bbn.rpki.test.objects;

import java.util.ArrayList;


/**
 * A specific class for List<Pair>
 *
 * @author tomlinso
 */
public class PairList extends ArrayList<Pair> {

  /**
   * @param list
   */
  public PairList(PairList list) {
    super(list);
  }

  /**
   * Default constructor
   */
  public PairList() {
    super();
  }
}
