/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Methods for dealing with the OS (Linux)
 *
 * @author tomlinso
 */
public class OS {
  /**
   * Execute a pipeline
   * @param stdin
   * @param stdout
   * @param stderr
   * @param commands
   * @throws IOException
   */
  public static void exec(InputStream stdin, OutputStream stdout, OutputStream stderr, String[]...commands) throws IOException {
    Runtime runtime = Runtime.getRuntime();
    List<Thread> threads = new ArrayList<Thread>();
    List<Process> processes = new ArrayList<Process>();
    try {
      OutputStream os = stdout;
      for (int i = 0, n = commands.length; i < n; i++) {
        String[] cmd = commands[i];
        final Process p = runtime.exec(cmd, null, Util.RPKI_ROOT);
        processes.add(p);
        if (stdin != null && i < n - 1) {
          // Need a separate thread to run the pipe
          final InputStream inputForProcess = stdin;
          Thread t = new Thread("pipe") {
            @Override
            public void run() {
              try {
                transferBytes(inputForProcess, p.getOutputStream());
              } catch (IOException e) {
                e.printStackTrace();
              }
            }
          };
          threads.add(t);
          t.start();
        }
        stdin = p.getInputStream();
      }
      if (stdout != null && stdin != null) {
        transferBytes(stdin, os);
      }
      for (Process p : processes) {
        try {
          p.waitFor();
        } catch (InterruptedException e) {
          // ignore
        }
      }
    } finally {
      for (Process p : processes) {
        p.destroy();
      }
      for (Process p : processes) {
        try {
          p.waitFor();
        } catch (InterruptedException e) {
          // ignore
        }
      }
      for (Thread t : threads) {
        try {
          t.join();
        } catch (InterruptedException e) {
          // ignore
        }
      }
    }
  }

  protected static void transferBytes(InputStream inputStream, OutputStream outputStream) throws IOException {
    byte[] bf = new byte[10000];
    int nb;
    while ((nb = inputStream.read(bf)) > 0) {
      outputStream.write(bf, 0, nb);
    }
  }
}
