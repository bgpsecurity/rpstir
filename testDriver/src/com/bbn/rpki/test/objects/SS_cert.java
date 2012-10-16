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

  /**
   * @param parent
   * @param ttl
   * @param siaPath
   * @param nickname
   * @param dirPath
   * @param subjKeyFile
   */
  public SS_cert(CA_Object parent, int ttl, String siaPath, String nickname, String dirPath, String subjKeyFile) {
    super(parent,
          ttl,
          dirPath,
          nickname,
          siaPath,
          new IPRangeList(IPRangeType.as),
          new IPRangeList(IPRangeType.ipv4),
          new IPRangeList(IPRangeType.ipv6),
          subjKeyFile,
          "CERTIFICATE",
        "selfsigned=True");
    this.sia = "r:rsync://" + siaPath + ",m:rsync://" + siaPath + Util.b64encode_wrapper(this.ski) + ".mft";
  }
}
