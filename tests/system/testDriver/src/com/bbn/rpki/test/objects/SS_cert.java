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
  public SS_cert(CA_Object parent,
                 long validityStartTime,
                 long validityEndTime,
                 String siaPath,
                 String nickname,
                 String dirPath,
                 IPRangeList asList,
                 IPRangeList ipv4List,
                 IPRangeList ipv6List,
                 String subjKeyFile) {
    super(parent,
          validityStartTime,
          validityEndTime,
          dirPath,
          nickname,
          siaPath,
          asList,
          ipv4List,
          ipv6List,
          subjKeyFile,
          "CERTIFICATE",
        "selfsigned=True");
    this.sia = "r:rsync://" + siaPath + ",m:rsync://" + siaPath + Util.b64encode_wrapper(this.ski) + ".mft";
  }
}
