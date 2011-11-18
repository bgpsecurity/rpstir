/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Roa extends CMS {

  private final int asID;
  private final IPRangeList roaipv4;
  private final IPRangeList roaipv6;
  private final String dir_path;

  /**
   * @param myFactory
   * @param ee_object
   */
  public Roa(RoaFactory myFactory, EE_Object ee_object) {
    super(ee_object.certificate.outputfilename, ee_object.certificate.subjkeyfile);
    // Pull the info we need from our ee_object
    this.asID           = myFactory.asid;
    this.roaipv4        = ee_object.subAllocateIPv4(myFactory.ROAipv4List);
    this.roaipv6        = ee_object.subAllocateIPv6(myFactory.ROAipv6List);
    this.outputfilename = REPO_PATH + "/" + ee_object.path_ROA;
    // Make our directory to place our ROA if it doesn't already exist
    dir_path = REPO_PATH + ee_object.parent.SIA_path;
    
    Util.writeConfig(this);
    Util.create_binary(this, "ROA");
  }

}
