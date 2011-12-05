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
public class IANAFactory extends FactoryBase {
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
  
  IPRangeList ipv4List = new IPRangeList(IPRangeType.ipv4);
  IPRangeList ipv6List = new IPRangeList(IPRangeType.ipv6);
  IPRangeList asList = new IPRangeList(IPRangeType.as);
  
  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#getIPV4RangeList()
   */
  @Override
  public IPRangeList getIPV4RangeList() {
    return ipv4List;
  }
  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#getIPV6RangeList()
   */
  @Override
  public IPRangeList getIPV6RangeList() {
    return ipv6List;
  }
  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#getASRangeList()
   */
  @Override
  public IPRangeList getASRangeList() {
    return asList;
  }
}
