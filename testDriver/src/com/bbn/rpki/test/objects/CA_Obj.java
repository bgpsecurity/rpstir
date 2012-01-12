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
public abstract class CA_Obj implements Constants {
  /** the name of the output file for the file created for this object */
  public String outputfilename;

  /**
   * Fill in values to be written to config file
   * Subclasses may override, but must invoke super.getFieldMap
   * @param map the Map to put key/value pairs into
   */
  public void getFieldMap(Map<String, Object> map) {
    map.put("outputfilename", outputfilename);
  }
}
