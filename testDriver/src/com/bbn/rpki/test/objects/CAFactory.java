/*
 * Created on Oct 17, 2012
 */
package com.bbn.rpki.test.objects;

import java.util.List;

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
  CA_Object create(CA_Object parent, int id) {
    CA_Object caObject = new CA_Object(this, parent, id, null, ttl, bluePrintName,
                                       serverName,
                                       breakAway);
    caObject.takeAS(asList, null);
    caObject.takeIPv4(ipv4List, null);
    caObject.takeIPv6(ipv6List, null);
    return caObject;
  }
}
