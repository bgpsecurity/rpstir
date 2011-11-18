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
public class EE_Object extends Allocator {
  private final IPRangeList ipv4Resources;
  private final IPRangeList ipv6Resources;
  private final IPRangeList asResources;
  private final String bluePrintName;
  private final FactoryBase myFactory;
  final CA_Object parent;
  private final List<EE_Object> children;
  public final EE_cert certificate;
  private final String SIA_path;
  private final int id;
  final String path_ROA;
 
  EE_Object(Factory myFactory,CA_Object parent) {

      this.bluePrintName = myFactory.bluePrintName;
      this.myFactory = myFactory;
      this.parent = parent;
      
      // List initialization
      this.children = new ArrayList<EE_Object>();
      this.ipv4Resources = parent.subAllocateIPv4(myFactory.ipv4List);
      this.ipv6Resources = parent.subAllocateIPv6(myFactory.ipv6List);
      this.asResources = parent.subAllocateAS(myFactory.asList);
      this.ipv4ResourcesFree = new IPRangeList(this.ipv4Resources);
      this.ipv6ResourcesFree = new IPRangeList(this.ipv6Resources);
      this.asResourcesFree = new IPRangeList(this.asResources);
  
      // Initialize our certificate
      this.certificate = new EE_cert(parent,
                                     myFactory,
                                 this.ipv4Resources,
                                 this.ipv6Resources,
                                 this.asResources);
      
      // Grab what I need from the certificate 
      // Obtain just the SIA path and cut off the r:rsync
      this.SIA_path = Util.removePrefix(this.certificate.sia, RSYNC_EXTENSION);
      this.id = this.certificate.serial;
      this.path_ROA = this.SIA_path;
  }
}
