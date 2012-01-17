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
public abstract class TypescriptLogger {
  /**
   * @param reader
   * @param styleName
   * @return a Reader equivalent to the supplied reader
   */
  public abstract Reader addSource(Reader reader, String styleName);

  /**
   * @param msg the message to log
   */
  public abstract void log(Object...msg);

  /**
   * @param fmt
   * @param args
   */
  public void format(String fmt, Object...args) {
    log(String.format(fmt, args));
  }

  /**
   * @param inputStreamReader
   * @param styleName
   */
  public abstract void suckOn(InputStreamReader inputStreamReader, String styleName);
}
