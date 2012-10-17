/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Crl extends CA_Obj {

  /** */
  public String parentcertfile;

  /** */
  public String parentkeyfile;

  /** */
  public String issuer;

  /** */
  public Calendar thisupdate;

  /** */
  public Calendar nextupdate;

  /** */
  public int crlnum;

  /** */
  public String aki;

  /** The following is not completely correct, but we currently generate no
   * n0n-empty CRLs. There is evidence that items should print as:
   * "1%201010190000Z, 1234565789%201010190000Z, 55%201010190000Z, 4%201010190000Z"
   * which I (ray) think is certificate serial number and date
   */
  public List<RevokedCert> revokedcertlist;

  /**
   * @param parent
   */
  public Crl(CA_Object parent) {
    super("CRL");
    Certificate parentCert = parent.getCertificate();
    this.parentcertfile  = parentCert.outputfilename;
    this.parentkeyfile   = parentCert.subjkeyfile;
    this.issuer          = parent.commonName;
    this.thisupdate      = Calendar.getInstance();
    // Not sure on this nextUpdate time frame
    this.nextupdate      = Calendar.getInstance();
    this.nextupdate.setTimeInMillis(this.thisupdate.getTimeInMillis());
    this.nextupdate.add(Calendar.DATE, parent.getTtl());
    this.crlnum          = parent.getNextChildSN();
    this.revokedcertlist = new ArrayList<RevokedCert>();
    this.aki             = parentCert.ski;

    // Create the output file directory if it doesn't exist
    String dir_path  = REPO_PATH + parent.SIA_path;
    this.outputfilename = dir_path + Util.b64encode_wrapper(this.aki)+".crl";
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    map.put("parentcertfile", parentcertfile);
    map.put("parentkeyfile", parentkeyfile);
    map.put("issuer", issuer);
    map.put("thisupdate", thisupdate);
    map.put("nextupdate", nextupdate);
    map.put("crlnum", crlnum);
    map.put("revokedcertlist", revokedcertlist);
    map.put("aki", aki);
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#appendString(java.lang.StringBuilder)
   */
  @Override
  public void appendString(StringBuilder sb) {
    sb.append(String.format("Crl(%s)", issuer));
  }
}
