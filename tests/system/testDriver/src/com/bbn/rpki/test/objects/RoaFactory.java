/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.actions.AllocateROAAction;
import com.bbn.rpki.test.actions.InitializeAction;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class RoaFactory extends Factory<AllocateROAAction> implements Constants {

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
                    List<Pair> roav4l,
                    List<Pair> roav6l,
                    int a) {
    super(name, ipv4, ipv6, as_list, child, server, null);
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
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.tasks.Model, com.bbn.rpki.test.objects.CA_Object, int)
   */
  @Override
  public AllocateROAAction create(Model model, InitializeAction initializeAction, CA_Object parent, int id) {
    if (DEBUG_ON) {
      System.out.println("creating a ROA for "+ bluePrintName);
    }

    int ipCount = ROAipv4List.size() + ROAipv6List.size();
    if (ipCount > 0) {
      TypedPair[] allPairs = new TypedPair[asid.size() + ipCount];
      int q = 0;
      q = addPairs(allPairs, q, IPRangeType.as, asid);
      q = addPairs(allPairs, q, IPRangeType.ipv4, ROAipv4List);
      q = addPairs(allPairs, q, IPRangeType.ipv6, ROAipv6List);

      return new AllocateROAAction(parent, AllocationId.get("roa-ini-" + parent.getNickname()), model, allPairs);
    }
    return null;
  }

  private int addPairs(TypedPair[] allPairs, int q, IPRangeType rangeType, List<Pair> pairs) {
    for (Pair pair : pairs) {
      allPairs[q++] = new TypedPair(rangeType, pair.tag, pair.arg);
    }
    return q;
  }
}
