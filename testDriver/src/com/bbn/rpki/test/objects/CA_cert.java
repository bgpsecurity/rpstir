/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class CA_cert extends Certificate {
  private static class S {
    String nickname;
    String sia_path;

    S(FactoryBase myFactory, CA_Object parent, int childId) {
      nickname = myFactory.bluePrintName + "-" + childId;

      if (myFactory.breakAway) {
        sia_path = myFactory.serverName + "/" + nickname + "/";
      } else {
        sia_path = parent.SIA_path + nickname + "/";
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
  CA_cert(CA_Object parent, int childId, FactoryBase myFactory, IPRangeList ipv4,
          IPRangeList ipv6, IPRangeList asList, String subjKeyFile) {
    this(parent, myFactory, new S(myFactory, parent, childId), ipv4, ipv6, asList, subjKeyFile);
  }

  private CA_cert(CA_Object parent, FactoryBase myFactory, S s, IPRangeList ipv4,
                  IPRangeList ipv6, IPRangeList asList, String subjKeyFile) {
    super(parent,
          myFactory,
          s.sia_path, 
          s.nickname,
          ipv4,
          ipv6,
          asList,
          subjKeyFile,
          "CERTIFICATE",
          "selfsigned=False");
    this.crldp = "rsync://" + parent.SIA_path + Util.b64encode_wrapper(parent.certificate.ski) + ".crl";
    this.aia   = "rsync://" + Util.removePrefix(parent.path_CA_cert, REPO_PATH);
    this.sia   = "r:rsync://" + s.sia_path + ",m:rsync://" + s.sia_path + Util.b64encode_wrapper(this.ski) + ".mft";

  }

  /**
   * @see com.bbn.rpki.test.objects.Certificate#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    map.put("crldp", crldp);
    map.put("aia", aia);
  }

}
