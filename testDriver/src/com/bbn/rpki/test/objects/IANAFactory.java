/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.List;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class IANAFactory extends FactoryBase<CA_Object> {
  /**
   * @param bluePrintName
   * @param childSpec
   * @param serverName
   * @param breakAway
   * @param ttl
   * @param subjKeyFile
   */
  protected IANAFactory(String bluePrintName, List<Pair> childSpec, String serverName,
                        boolean breakAway, int ttl, String subjKeyFile) {
    super(bluePrintName, childSpec, serverName, breakAway, ttl, subjKeyFile);
  }

  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object, int)
   */
  @Override
  CA_Object create(CA_Object parent, int id) {
    CA_Object caObject = new CA_Object(this, parent, id, null, ttl, bluePrintName,
                                       serverName,
                                       breakAway);
    caObject.addRcvdRanges(getEverything(IPRangeType.as));
    caObject.addRcvdRanges(getEverything(IPRangeType.ipv4));
    caObject.addRcvdRanges(getEverything(IPRangeType.ipv6));
    return caObject;
  }

  private IPRangeList getEverything(IPRangeType rangeType) {
    IPRangeList everything = new IPRangeList(rangeType);
    everything.addRange(BigInteger.ZERO, rangeType.getMax());
    return everything;
  }
}
