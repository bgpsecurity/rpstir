/*
 * Created on Nov 17, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class Sucker extends Thread {
  private final InputStream stream;
  private final StringBuilder sb = new StringBuilder();
  private IOException threadException;

  Sucker(InputStream is, String name) {
    super(name);
    this.stream = is;
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
    Reader r = new InputStreamReader(stream);
    char[] bf = new char[1024];
    int n;
    try {
      while ((n = r.read(bf)) > 0) {
        String s = new String(bf, 0, n);
        sb.append(s);
      }
      r.close();
    } catch (IOException e) {
      threadException = e;
    }
  }
}
