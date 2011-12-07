/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.ArrayList;
import java.util.List;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Roa extends CMS {

  public final List<String> asID;
  public final IPRangeList roaipv4;
  public final IPRangeList roaipv6;
  private final String dir_path;

  /**
   * @param myFactory
   * @param ee_object
   */
  public Roa(RoaFactory myFactory, EE_Object ee_object) {
    super(ee_object.certificate.outputfilename, ee_object.certificate.subjkeyfile);
    // Pull the info we need from our ee_object
    this.asID           = new ArrayList<String>(myFactory.asid.size());
    for (Pair pair : myFactory.asid) {
      asID.add(String.format("'%s'", pair.arg.toString()));
    }
    this.roaipv4        = ee_object.subAllocateIPv4(myFactory.ROAipv4List);
    this.roaipv6        = ee_object.subAllocateIPv6(myFactory.ROAipv6List);
    this.outputfilename = REPO_PATH + "/" + ee_object.path_ROA;
    // Make our directory to place our ROA if it doesn't already exist
    dir_path = REPO_PATH + ee_object.parent.SIA_path;
    
    Util.writeConfig(this);
    Util.create_binary(this, "ROA");
  }

}
