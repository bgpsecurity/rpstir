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

    S(FactoryBase myFactory, Allocator parent, int childId) {

    }
  }

  /** The crl dp */
  public final String crldp;

  /** The aia */
  public final String aia;

  /**
   * @param parent
   * @param asList
   * @param ipv4
   * @param ipv6
   * @param subjKeyFile
   * @param myFactory
   * @param siaPath
   * @param serial
   */
  CA_cert(CA_Object parent,
          long validityStartTime,
          long validityEndTime,
          String dirPath,
          String nickname,
          String sia_path,
          IPRangeList asList,
          IPRangeList ipv4,
          IPRangeList ipv6,
          String subjKeyFile) {
    super(parent,
          validityStartTime,
          validityEndTime,
          dirPath,
          nickname,
          sia_path,
          asList,
          ipv4,
          ipv6,
          subjKeyFile,
          "CERTIFICATE",
        "selfsigned=False");
    this.crldp = "rsync://" + parent.getSIA_path() + Util.b64encode_wrapper(parent.getCertificate().ski) + ".crl";
    this.aia   = "rsync://" + Util.removePrefix(outputfilename, REPO_PATH);
    this.sia   = "r:rsync://" + sia_path + ",m:rsync://" + sia_path + Util.b64encode_wrapper(this.ski) + ".mft";
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
