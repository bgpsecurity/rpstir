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
public abstract class FactoryBase {

  /**
   * bp name
   */
  protected String bluePrintName;
  /**
   * time to live in days
   */
  protected int ttl;
  String subjKeyFile;
  String serverName;
  boolean breakAway;
  String SIA_path;

  final List<Pair> childSpec;

  abstract IPRangeList getIPV4RangeList();
  abstract IPRangeList getIPV6RangeList();
  abstract IPRangeList getASRangeList();

  protected FactoryBase(String bluePrintName,
                        List<Pair> childSpec,
                        String serverName,
                        boolean breakAway,
                        int ttl,
                        String subjKeyFile) {
    this.bluePrintName = bluePrintName;
    this.childSpec = childSpec;
    this.serverName = serverName;
    this.breakAway = breakAway;
    this.ttl = ttl;
    this.subjKeyFile = subjKeyFile;
  }

  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object)
   */
  Object create(CA_Object parent, int id) {
    return new CA_Object(this, parent, id, null);
  }
  /**
   * @return the serverName
   */
  public String getServerName() {
    return serverName;
  }

  /**
   * @return true if the server name here should be used
   */
  public boolean isBreakAway() {
    return breakAway;
  }
}
