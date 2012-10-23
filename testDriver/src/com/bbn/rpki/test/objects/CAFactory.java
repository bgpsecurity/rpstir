/*
 * Created on Oct 17, 2012
 */
package com.bbn.rpki.test.objects;

import java.util.List;

import com.bbn.rpki.test.actions.AllocateAction;
import com.bbn.rpki.test.actions.InitializeAction;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class CAFactory extends Factory<CA_Object> {

  /**
   * @param bluePrintName
   * @param ipv4List
   * @param ipv6List
   * @param asList
   * @param childSpec
   * @param serverName
   * @param breakAway
   * @param ttl
   * @param subjKeyFile
   */
  protected CAFactory(String bluePrintName, List<Pair> ipv4List, List<Pair> ipv6List,
                      List<Pair> asList, List<Pair> childSpec, String serverName,
                      boolean breakAway, int ttl, String subjKeyFile) {
    super(bluePrintName, ipv4List, ipv6List, asList, childSpec, serverName, breakAway, ttl, subjKeyFile);
  }

  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object, int)
   */
  @Override
  CA_Object create(Model model, InitializeAction initializeAction, CA_Object parent, int id) {
    CA_Object caObject = new CA_Object(this, parent, id, null, ttl, bluePrintName,
                                       serverName,
                                       breakAway);
    TypedPair[] allPairs = new TypedPair[asList.size() + ipv4List.size() + ipv6List.size()];
    if (allPairs.length > 0) {
      int q = 0;
      q = addPairs(allPairs, q, IPRangeType.as, asList);
      q = addPairs(allPairs, q, IPRangeType.ipv4, ipv4List);
      q = addPairs(allPairs, q, IPRangeType.ipv6, ipv6List);

      AllocateAction allocateAction = new AllocateAction(parent, caObject, AllocationId.get("ini-" + caObject.getNickname()), model, allPairs);
      initializeAction.addAction(allocateAction);
    }
    return caObject;
  }

  private int addPairs(TypedPair[] allPairs, int q, IPRangeType rangeType, List<Pair> pairs) {
    for (Pair pair : pairs) {
      allPairs[q++] = new TypedPair(rangeType, pair.tag, pair.arg);
    }
    return q;
  }
}
