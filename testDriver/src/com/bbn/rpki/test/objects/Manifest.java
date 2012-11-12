/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Manifest extends CMS {

  /** The date of this update  */
  public final Calendar thisupdate;

  /** The date of the next expected update */
  public final Calendar nextupdate;

  private final CA_Object parent;
  private EE_cert eeCert;
  private final int manNum;

  /**
   * Construct a new manifest
   * 
   * @param parent
   * @param myFactory
   */
  public Manifest(CA_Object parent) {
    super("MANIFEST");
    this.parent = parent;
    this.thisupdate = Calendar.getInstance();
    // Not sure on this nextUpdate time frame
    this.nextupdate = Calendar.getInstance();
    this.nextupdate.setTimeInMillis(parent.getValidityEndTime());
    this.manNum = parent.getNextManifestNumber();
    // Chop off our rsync:// portion and append the repo path
    this.outputfilename = REPO_PATH + parent.getSIA_path() + Util.b64encode_wrapper(parent.getCertificate().ski) + ".mft";

  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    File dirname = new File(REPO_PATH, parent.getSIA_path());
    List<String> fileList = new ArrayList<String>();
    for (File f : dirname.listFiles()) {
      if (f.isFile()) {
        fileList.add(f.getName() + "%" + Util.generate_file_hash(f));
      }
    }
    map.put("manNum", manNum);
    map.put("thisupdate", thisupdate);
    map.put("nextupdate", nextupdate);
    map.put("fileList", fileList);
  }

  /**
   * @see com.bbn.rpki.test.objects.CMS#getEECert()
   */
  @Override
  protected EE_cert getEECert() {
    if (eeCert == null) {
      // Create single-use EE certificate
      eeCert = new EE_cert(parent,
                           parent.getValidityStartTime(),
                           parent.getValidityEndTime(),
                           "Manifest-EE",
                           parent.getSIA_path() + "EE-" + manNum + "/",
                           IPRangeList.IPV4_EMPTY,
                           IPRangeList.IPV6_EMPTY,
                           IPRangeList.AS_EMPTY);
    }
    return eeCert;
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#appendString(java.lang.StringBuilder)
   */
  @Override
  public void appendString(StringBuilder sb) {
    sb.append(String.format("Manifest(%s)", parent.getCommonName()));
  }
}
