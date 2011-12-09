/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.ArrayList;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class CA_Object extends Allocator {

  /** sia directory path (ends with /) */
  public String SIA_path;
  /** cert common name */
  public String commonName;
  /** the certificate itself */
  public Certificate certificate;
  /** The location (path to) the certificate */
  public String path_CA_cert;
  /** My factory */
  public FactoryBase myFactory;

  private int nextChildSN;
  final String bluePrintName;
  private final CA_Object parent;
  final List<CA_Object> children = new ArrayList<CA_Object>();
  final List<Manifest> manifests = new ArrayList<Manifest>();
  final List<Roa> roas = new ArrayList<Roa>();
  final List<Crl> crl = new ArrayList<Crl>();
  private final String manifest_path;
  private final int id;
  private final String nickName;

  /**
   * @param factoryBase 
   * @param myFactory
   * @param parent
   * @param subjKeyFile
   */
  public CA_Object(FactoryBase factoryBase, CA_Object parent, String subjKeyFile) {
    this.nextChildSN = 0;
    this.bluePrintName = factoryBase.bluePrintName;
    this.myFactory = factoryBase;
    this.parent = parent;

    if (parent != null) {
      Factory myFactory = (Factory) factoryBase;
      this.ipv4Resources = parent.subAllocateIPv4(myFactory.ipv4List);
      this.ipv6Resources = parent.subAllocateIPv6(myFactory.ipv6List);
      this.asResources = parent.subAllocateAS(myFactory.asList);
    } else {
      //  trust anchor CA
      IANAFactory myFactory = (IANAFactory) factoryBase;
      this.ipv4Resources = myFactory.ipv4List;
      this.ipv6Resources = myFactory.ipv6List;
      this.asResources = myFactory.asList;
    }
    this.ipv4ResourcesFree = new IPRangeList(this.ipv4Resources);
    this.ipv6ResourcesFree = new IPRangeList(this.ipv6Resources);
    this.asResourcesFree = new IPRangeList(this.asResources);

    // Initialize our certificate
    if (parent != null) {
      this.certificate = new CA_cert(parent,
                                     factoryBase,
                                     this.ipv4Resources,
                                     this.ipv6Resources,
                                     this.asResources,
                                     subjKeyFile);
    } else {
      this.certificate = new SS_cert(parent, myFactory,
                                     subjKeyFile);
    }
    // Grab what I need from the certificate 
    // Obtain just the SIA path and cut off the r:rsync://
    String[] sia_list = this.certificate.sia.substring(RSYNC_EXTENSION.length()).split(",");
    this.SIA_path = sia_list[0].substring(0, sia_list[0].length());
    this.manifest_path = Util.removePrefix(sia_list[1], RSYNC_EXTENSION);
    this.id = this.certificate.serial;
    this.path_CA_cert = this.certificate.outputfilename;
    this.nickName= this.myFactory.bluePrintName + "-" + this.id;
    if (parent != null)
      this.commonName = parent.commonName + "." + this.nickName;
    else
      this.commonName = this.nickName;
  }

  public int getNextChildSN() {
    int nextChild = this.nextChildSN;
    this.nextChildSN += 1;
    return nextChild;
  }
}
