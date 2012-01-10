/*
 * Created on Jan 9, 2012
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class PregeneratedKeys {
  
  private static final int KEYS_DESIRED = 10000;
  
  private static List<String> pregeneratedKeyFileNames = null;

  private static int pregeneratedKeyIndex;

  /**
   * @return the name of the pregenerated key file
   */
  public static String getPregeneratedKey() {
    File pregeneratedKeyDir = new File("pregeneratedKeys");
    if (pregeneratedKeyFileNames == null) {
      // Read the pre-generated keys
      if (!pregeneratedKeyDir.isDirectory()) {
        if (pregeneratedKeyDir.exists()) {
          pregeneratedKeyDir.delete();
        }
        pregeneratedKeyDir.mkdirs();
      }
      String[] fileNames = pregeneratedKeyDir.list(new FilenameFilter() {

        @Override
        public boolean accept(File arg0, String name) {
          return name.endsWith(".key");
        }
      });
      pregeneratedKeyFileNames = new ArrayList<String>(Arrays.asList(fileNames));
      int keyIndex = pregeneratedKeyFileNames.size();
      // Add up to 100 additional keys up to KEYS_DESIRED
      int endIndex = Math.min(KEYS_DESIRED, keyIndex + 100);
      final LinkedBlockingDeque<String> queue = new LinkedBlockingDeque<String>();
      for (; keyIndex < endIndex; keyIndex++) {
        String name = String.format("genkey_%05d.key", keyIndex);
        String path = new File(pregeneratedKeyDir, name).getPath();
        queue.add(path);
        pregeneratedKeyFileNames.add(name);
      }
      int ncpus = Runtime.getRuntime().availableProcessors();
      Thread[] threads = new Thread[ncpus];
      for (int i = 0; i < threads.length; i++) {
        Thread t = new Thread("Worker " + i) {
          @Override
          public void run() {
            String path;
            while ((path = queue.poll()) != null) {
              Util.exec("gen_key", false, null, null, 
                        null,
                        "../../cg/tools/gen_key",
                        path, "2048");
            }
          }
        };
        threads[i] = t;
        t.start();
      }
      for (int i = 0; i < threads.length; i++) {
        Thread t = threads[i];
        try {
          t.join();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      pregeneratedKeyIndex = 0;
    }
    String name = pregeneratedKeyFileNames.get(pregeneratedKeyIndex++);
    String path = new File(pregeneratedKeyDir, name).getPath();
    if (pregeneratedKeyIndex >= pregeneratedKeyFileNames.size()) {
      pregeneratedKeyIndex = 0;
    }
    return path;
  }
}
