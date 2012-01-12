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
  private static class S {
    /**
     * @param parent
     * @param myFactory
     */
    public S(CA_Object parent, Factory myFactory) {
      eeCert = new EE_cert(parent, myFactory, IPRangeList.IPV4_EMPTY, IPRangeList.IPV6_EMPTY, IPRangeList.AS_EMPTY);
    }

    EE_cert eeCert;
  }

  /** Manifest number */
  public final int manNum;

  /** The date of this update  */
  public final Calendar thisupdate;

  /** The date of the next expected update */
  public final Calendar nextupdate;

  /** Information about the files in this manifest */
  public final List<String> fileList;
  
  /**
   * Construct a new manifest
   * 
   * @param parent
   * @param myFactory
   */
  public Manifest(CA_Object parent, Factory myFactory) {
    this(parent, myFactory, new S(parent, myFactory));
  }
  
  private Manifest(CA_Object parent, FactoryBase myFactory, S s) {
    super(s.eeCert.outputfilename, s.eeCert.subjkeyfile);
    this.manNum = s.eeCert.serial;
    this.thisupdate = Calendar.getInstance();
    // Not sure on this nextUpdate time frame
    this.nextupdate = Calendar.getInstance();
    this.nextupdate.setTimeInMillis(this.thisupdate.getTimeInMillis());
    this.nextupdate.add(Calendar.DATE, parent.myFactory.ttl);
    // Chop off our rsync:// portion and append the repo path
    this.outputfilename = REPO_PATH + parent.SIA_path + Util.b64encode_wrapper(parent.certificate.ski) + ".mft";
    
    File dirname = new File(REPO_PATH, parent.SIA_path);
    List<String> fileList = new ArrayList<String>();
    for (File f : dirname.listFiles()) {
        if (f.isFile()) {
            fileList.add(f.getName() + "%" + Util.generate_file_hash(f));
        }
    }
    
    this.fileList = fileList;

    Util.writeConfig(this);
    Util.create_binary(this, "MANIFEST");
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    map.put("manNum", manNum);
    map.put("thisupdate", thisupdate);
    map.put("nextupdate", nextupdate);
    map.put("fileList", fileList);
  }
}
