/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.Map;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public abstract class CMS extends CA_Obj {

  /** location of the cert */
   public final String EECertLocation;
   
   /** location of the key */
  public final String EEKeyLocation;

  /**
   * @param eeCertLocation
   * @param eeKeyLocation
   */
  public CMS(String eeCertLocation, String eeKeyLocation) {
    this.EECertLocation = eeCertLocation;
    this.EEKeyLocation = eeKeyLocation;
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    map.put("EECertLocation", EECertLocation);
    map.put("EEKeyLocation", EEKeyLocation);
  }
}
