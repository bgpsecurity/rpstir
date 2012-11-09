/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public abstract class Factory<T> extends FactoryBase<T> {

  /** Initial allocation requests that should be made */
  protected List<Pair> asList;

  /** Initial allocation requests that should be made */
  protected List<Pair> ipv4List;

  /** Initial allocation requests that should be made */
  protected List<Pair> ipv6List;


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
  protected Factory(String bluePrintName,
                    List<Pair> ipv4List,
                    List<Pair> ipv6List,
                    List<Pair> asList,
                    List<Pair> childSpec,
                    String serverName,
                    String subjKeyFile) {
    super(bluePrintName, childSpec, serverName, subjKeyFile);
    this.ipv4List = ipv4List;
    this.ipv6List = ipv6List;
    this.asList = asList;
  }
}
