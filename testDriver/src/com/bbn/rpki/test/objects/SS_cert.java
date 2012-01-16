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

    String siaPath;
    String nickname;

    S(Allocator parent, FactoryBase myFactory) {
      nickname = myFactory.bluePrintName + "-0";
      siaPath = myFactory.serverName + "/" + nickname + "/";
    }
  }

  /**
   * @param parent
   * @param myFactory
   * @param subjKeyFile
   */
  public SS_cert(CA_Object parent, FactoryBase myFactory, String subjKeyFile) {
    this(parent, myFactory, new S(parent, myFactory), subjKeyFile);
  }

  private SS_cert(CA_Object parent, FactoryBase myFactory, S s, String subjKeyFile) {
    super(parent,
          myFactory,
          s.siaPath,
          s.nickname,
          new IPRangeList(IPRangeType.ipv4),
          new IPRangeList(IPRangeType.ipv6),
          new IPRangeList(IPRangeType.as),
          subjKeyFile,
          "CERTIFICATE",
    "selfsigned=True");
    this.sia = "r:rsync://" + s.siaPath + ",m:rsync://" + s.siaPath + Util.b64encode_wrapper(this.ski) + ".mft";
  }
}
