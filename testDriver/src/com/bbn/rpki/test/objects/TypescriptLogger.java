/*
 * Created on Dec 13, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.InputStreamReader;
import java.io.Reader;

/**
 * Interface for classes that can log a typescript
 *
 * @author tomlinso
 */
public interface TypescriptLogger {
  /**
   * @param reader
   * @param styleName
   * @return a Reader equivalent to the supplied reader
   */
  public Reader addSource(Reader reader, String styleName);

  /**
   * @param msg
   * @param style
   */
  public void log(Object msg, String style);

  /**
   * @param asList
   */
  public void log(Object msg);

  /**
   * @param inputStreamReader
   * @param styleName 
   */
  public void suckOn(InputStreamReader inputStreamReader, String styleName);
}
