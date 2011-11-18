/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class SS_cert extends Certificate {
  private static class S {

    public String siaPath;
    public int serial = 0;
    public IPRangeList ipv4 = new IPRangeList(IPRangeType.ipv4);
    public IPRangeList ipv6 = new IPRangeList(IPRangeType.ipv6);
    public IPRangeList asList = new IPRangeList(IPRangeType.as);
    
    S(CA_Object parent, FactoryBase myFactory) {
      String nickName = myFactory.bluePrintName + "-" + serial;
      siaPath = myFactory.serverName + "/" + nickName + "/";
    }
  }
 
  /**
   * @param parent
   * @param myFactory
   * @param siaPath
   * @param serial
   * @param ipv4
   * @param ipv6
   * @param asList
   * @param subjKeyFile
   */
  public SS_cert(CA_Object parent, FactoryBase myFactory, String subjKeyFile) {
    this(parent, myFactory, new S(parent, myFactory), subjKeyFile);
  }
  
  private SS_cert(CA_Object parent, FactoryBase myFactory, S s, String subjKeyFile) {
    super(parent, myFactory, s.siaPath, s.serial, s.ipv4, s.ipv6, s.asList, subjKeyFile);
    this.sia = "r:rsync://" + s.siaPath + "/,m:rsync://" + s.siaPath + "/" + Util.b64encode_wrapper(this.ski) + ".mft";
    Util.writeConfig(this);
    Util.create_binary(this, "CERTIFICATE", "selfsigned=True");
  }
}
