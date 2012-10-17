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
  final String bluePrintName;
  final CA_Object parent;
  final List<EE_Object> children;
  final String SIA_path;
  final int id;
  final String path_ROA;
  EE_cert certificate;
  private final int ttl;

  public EE_Object(int ttl, List<Pair> asList, List<Pair> ipv4List, List<Pair> ipv6List, String bluePrintName, CA_Object parent) {

    this.bluePrintName = bluePrintName;
    this.parent = parent;
    this.ttl = ttl;

    // List initialization
    this.children = new ArrayList<EE_Object>();
    this.addRcvdRanges(parent.subAllocateIPv4(ipv4List));
    this.addRcvdRanges(parent.subAllocateIPv6(ipv6List));
    this.addRcvdRanges(parent.subAllocateAS(asList));

    // Initialize our certificate
    Certificate certificate = getCertificate();

    // Grab what I need from the certificate
    // Obtain just the SIA path and cut off the r:rsync
    this.SIA_path = Util.removePrefix(certificate.sia, RSYNC_EXTENSION);
    this.id = certificate.serial;
    this.path_ROA = this.SIA_path;
  }

  /**
   * @return the Certificate for this EE
   */
  public EE_cert getCertificate() {
    if (this.certificate == null || isModified()) {
      this.certificate = new EE_cert(parent,
                                     ttl,
                                     bluePrintName + "-" + id,
                                     parent.SIA_path + "EE-" + id + "/",
                                     this.getRcvdRanges(IPRangeType.ipv4),
                                     this.getRcvdRanges(IPRangeType.ipv6),
                                     this.getRcvdRanges(IPRangeType.as));
      setModified(false);
    }
    return this.certificate;
  }

  /**
   * 
   */
  public void returnAllocation() {
    for (IPRangeType rangeType : IPRangeType.values()) {
      IPRangeList ranges = this.getRcvdRanges(rangeType);
      this.removeRcvdRanges(ranges);
      parent.addFreeRanges(ranges);

    }
    // Don't worry about our resources. We will never be used again.
  }
}
