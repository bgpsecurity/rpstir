/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class CA_cert extends Certificate {
  private static class S {
    int serial;
    String sia_path;
    S(FactoryBase myFactory, CA_Object parent) {
      serial = parent.getNextChildSN();
      // Local variable to help with naming conventions
      String nickName = myFactory.bluePrintName + "-" + serial;
         
      if (myFactory.breakAway) {
        sia_path = myFactory.serverName + "/" + nickName + "/";
      } else {
        sia_path = parent.SIA_path + nickName + "/";
      }
    }
  }

  /** The crl dp */
  public final String crldp;
  
  /** The aia */
  public final String aia;
  
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
  CA_cert(CA_Object parent, FactoryBase myFactory, IPRangeList ipv4,
          IPRangeList ipv6, IPRangeList asList, String subjKeyFile) {
    this(parent, myFactory, new S(myFactory, parent), ipv4, ipv6, asList, subjKeyFile);
  }

  private CA_cert(CA_Object parent, FactoryBase myFactory, S s, IPRangeList ipv4,
                  IPRangeList ipv6, IPRangeList asList, String subjKeyFile) {
    super(parent, myFactory, s.sia_path, s.serial, ipv4, ipv6, asList, subjKeyFile);
    this.crldp = "rsync://" + parent.SIA_path + Util.b64encode_wrapper(parent.certificate.ski) + ".crl";
    this.aia   = "rsync://" + Util.removePrefix(parent.path_CA_cert, REPO_PATH);
    this.sia   = "r:rsync://" + s.sia_path + ",m:rsync://" + s.sia_path + Util.b64encode_wrapper(this.ski) + ".mft";
    Util.writeConfig(this);
    Util.create_binary(this, "CERTIFICATE selfsigned=False");

  }
}
