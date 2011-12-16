/*
 * Created on Nov 17, 2011
 */
package com.bbn.rpki.test.util;

import java.io.IOException;
import java.io.Reader;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class Sucker extends Thread {
  private final Reader reader;
  private final StringBuilder sb = new StringBuilder();
  private IOException threadException;

  /**
   * @param is
   * @param name
   * @param out
   */
  public Sucker(Reader is, String name) {
    super(name);
    this.reader = is;
    start();
  }
  
  /**
   * @return the string captured from the process
   * @throws IOException
   */
  public String getString() throws IOException {
    if (threadException != null) {
      throw threadException;
    }
    return sb.toString();
  }
  
  /**
   * @see java.lang.Thread#run()
   */
  @Override
  public void run() {
    char[] bf = new char[1024];
    int n;
    try {
      while ((n = reader.read(bf)) > 0) {
        String s = new String(bf, 0, n);
        sb.append(s);
      }
      reader.close();
    } catch (IOException e) {
      threadException = e;
    }
  }
}
