/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class RoaFactory extends Factory implements Constants {

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
    asid = new ArrayList<Pair>(1);
    asid.add(new Pair("r", BigInteger.valueOf(a)));
    ROAipv4List = roav4l;
    ROAipv6List = roav6l;
  }
  /** asid */
  public List<Pair> asid;

  /** ROAipv4List */
  public List<Pair> ROAipv4List;

  /** ROAipv6List */
  public List<Pair> ROAipv6List;


  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object)
   */
  @Override
  public Roa create(CA_Object parent, int id) {
    if (DEBUG_ON) {
      System.out.println("creating a ROA for "+ bluePrintName);
    }

    EE_Object ee_object = new EE_Object(this, parent);
    return new Roa(this, ee_object);
  }
}
