/*
 * Created on Nov 8, 2011
 */
package com.bbn.rpki.test.objects;


/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class CMS extends CA_Obj {

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
}
