/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;
import java.util.Map;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public abstract class CMS extends CA_Obj {

  /**
   * @param xargs extra args to pase to create_object
   */
  public CMS(String...xargs) {
    super(xargs);
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    EE_cert ee_cert = getEECert();
    map.put("EECertLocation", ee_cert.outputfilename);
    map.put("EEKeyLocation", ee_cert.subjkeyfile);
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#appendObjectsToWrite(java.util.List)
   */
  @Override
  public void appendObjectsToWrite(List<CA_Obj> list) {
    CA_Obj eeCert = getEECert();
    list.add(eeCert);
    eeCert.appendObjectsToWrite(list);
  }

  protected abstract EE_cert getEECert();
}
