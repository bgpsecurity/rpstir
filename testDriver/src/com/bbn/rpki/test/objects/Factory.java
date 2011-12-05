/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Factory extends FactoryBase {

  /** Initial allocation requests that should be made */
  public List<Pair> asList;

  /** Initial allocation requests that should be made */
  public List<Pair> ipv4List;

  /** Initial allocation requests that should be made */
  public List<Pair> ipv6List;


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
  public Factory(String bluePrintName, 
                 List<Pair> ipv4List,
                 List<Pair> ipv6List,
                 List<Pair> asList,
                 List<Pair> childSpec,
                 String serverName,
                 boolean breakAway,
                 int ttl,
                 String subjKeyFile) {
    super(bluePrintName, childSpec, serverName, breakAway, ttl, subjKeyFile);
    this.ipv4List = ipv4List;
    this.ipv6List = ipv6List;
    this.asList = asList;
    
    // TODO Auto-generated constructor stub
  }

  /**
   * @return the part
   */
  @Override
  public IPRangeList getIPV4RangeList() {
    IPRangeList ipv4Everything = new IPRangeList(IPRangeType.ipv4);
    ipv4Everything.addRange(BigInteger.ZERO, new BigInteger("0xffffffff"));
    return RangeAllocator.allocate(ipv4Everything, ipv4List, false);
  }
  
  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#getIPV6RangeList()
   */
  @Override
  public IPRangeList getIPV6RangeList() {
    IPRangeList ipv6Everything = new IPRangeList(IPRangeType.ipv6);
    ipv6Everything.addRange(BigInteger.ZERO, 
                            new BigInteger("0xffffffffffffffffffffffffffffffff"));
    return RangeAllocator.allocate(ipv6Everything, ipv6List, false);
  }
  
  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#getASRangeList()
   */
  @Override
  public IPRangeList getASRangeList() {
    IPRangeList asEverything = new IPRangeList(IPRangeType.as);
    asEverything.addRange(BigInteger.ZERO, 
                          new BigInteger("0xffffffff"));
    return RangeAllocator.allocate(asEverything, asList, false);
  }
}
