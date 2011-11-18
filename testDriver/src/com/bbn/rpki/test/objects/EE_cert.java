/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class EE_cert extends Certificate {
  private static class S {

    public String siaPath;
    public int serial;
    public String subjKeyFile;

    /**
     * @param parent
     * @param myFactory
     */
    public S(CA_Object parent, FactoryBase myFactory) {
      serial = parent.getNextChildSN();
      // Local variable to help with naming conventions
      String nickName = "EE-" + serial;

      siaPath = parent.SIA_path + nickName + "/";
    }
  }

  /** */
  public final Object aia;
  
  /** */
  public final Object crldp;
  
  /**
   * @param parent
   * @param myFactory
   * @param siaPath
   * @param serial
   * @param ipv4
   * @param ipv6
   * @param asList
   * @param subjkeyfile
   */
  EE_cert(CA_Object parent, Factory myFactory, IPRangeList ipv4,
          IPRangeList ipv6, IPRangeList asList) {
    this(parent, myFactory, new S(parent, myFactory), ipv4, ipv6, asList);
    // TODO Auto-generated constructor stub
  }
  
  private EE_cert(CA_Object parent, Factory myFactory, S s, IPRangeList ipv4,
                  IPRangeList ipv6, IPRangeList asList) {
    super(parent, myFactory, s.siaPath, s.serial, ipv4, ipv6, asList, s.subjKeyFile);
    this.aia   = "rsync://" + Util.removePrefix(parent.path_CA_cert, REPO_PATH);
    this.crldp = "rsync://" + parent.SIA_path + Util.b64encode_wrapper(parent.certificate.ski) + ".crl";
    // Set our SIA based on the hash of our public key, which will be the name
    // of the ROA or Manifest this EE will be signing 
    if (myFactory.bluePrintName.equals("Manifest-EE")) {
        this.sia = "s:rsync://" + parent.SIA_path + Util.b64encode_wrapper(parent.certificate.ski) + ".mft";
        this.ipv4 = IPRangeList.IPV4_INHERIT;
        this.ipv6 = IPRangeList.IPV6_INHERIT;
        this.as_list = IPRangeList.AS_INHERIT;
    } else {
        this.sia = "s:rsync://" + parent.SIA_path + Util.b64encode_wrapper(this.ski) + ".roa";
    }
    Util.writeConfig(this);
    Util.create_binary(this, "CERTIFICATE", "selfsigned=False");
  }

}
