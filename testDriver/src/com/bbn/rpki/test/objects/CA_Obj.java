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
public abstract class CA_Obj implements Constants {
  /** the name of the output file for the file created for this object */
  public String outputfilename;
  final String[] xargs;
  private boolean written = false;
  
  protected CA_Obj(String...xargs) {
    this.xargs = xargs;
  }
  
  /**
   * @return true if this object has been written
   */
  public boolean isWritten() {
    return written;
  }
  
  /**
   * Set written flag
   * @param b
   */
  public void setWritten(boolean b) {
    written = b;
  }
  
  /**
   * @param list the list to append to
   */
  public void appendObjectsToWrite(List<CA_Obj> list) {
    // Override if there are any sub objects
  }

  /**
   * Fill in values to be written to config file
   * Subclasses may override, but must invoke super.getFieldMap
   * @param map the Map to put key/value pairs into
   */
  public void getFieldMap(Map<String, Object> map) {
    map.put("outputfilename", outputfilename);
  }
}
