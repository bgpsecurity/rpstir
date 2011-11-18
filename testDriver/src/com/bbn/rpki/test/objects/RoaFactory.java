/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class RoaFactory extends Factory {

  /**
   * @param name
   * @param ipv4
   * @param ipv6
   * @param as_list
   * @param child
   * @param server
   * @param breakA
   * @param t
   * @param roav4l
   * @param roav6l
   * @param a
   */
  public RoaFactory(String name,
                    List<Pair> ipv4,
                    List<Pair> ipv6,
                    List<Pair> as_list,
                    List<Pair> child,
                    String server,
                    boolean breakA, 
                    Integer t, 
                    List<Pair> roav4l,
                    List<Pair> roav6l,
                    int a) {
    super(name, ipv4, ipv6, as_list, child, server, breakA, t, null);
    asid = a;
    ROAipv4List = roav4l;
    ROAipv6List = roav6l;
  }
  public int asid;
  public List<Pair> ROAipv4List;
  public List<Pair> ROAipv6List;

}
