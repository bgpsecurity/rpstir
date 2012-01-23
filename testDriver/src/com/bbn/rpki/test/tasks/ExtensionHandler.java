/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ExtensionHandler {
  static class Group {
    private final String extension;
    private final List<File> files;
    /**
     * @param extension
     * @param files
     */
    public Group(String extension, List<File> files) {
      super();
      this.extension = extension;
      this.files = files;
    }
    /**
     * @return the extension
     */
    public String getExtension() {
      return extension;
    }
    /**
     * @return the files
     */
    public List<File> getFiles() {
      return files;
    }
  }

  static class ExtensionFilter implements FileFilter {
    private final String extension;
    ExtensionFilter(String extension) {
      this.extension = extension;
    }

    @Override
    public boolean accept(File file) {
      return file.getName().endsWith("." + extension);
    }
  }

  private final Map<String, ExtensionFilter[]> breakdownMap = new TreeMap<String, ExtensionFilter[]>();

  /**
   * Constructor
   */
  public ExtensionHandler() {
    String[] extensions = {
        "cer",
        "mft",
        "crl",
        "roa",
    };
    ExtensionFilter[] filters = new ExtensionFilter[extensions.length];
    for (int i = 0; i < extensions.length; i++) {
      filters[i] = new ExtensionFilter(extensions[i]);
    }
    // Compute all orderings
    // The number of orderings is factorial(number of extensions)
    // Step through them and select the corresponding extension
    int factorial = 1;
    for (int q = extensions.length; q > 1; q--) {
      factorial *= q;
    }
    StringBuilder sb = new StringBuilder();
    for (int combo = 0; combo < factorial; combo++) {
      ExtensionFilter[] selectedFilters = new ExtensionFilter[extensions.length];
      sb.setLength(0);
      int filterIx = 0;
      int[] available = new int[extensions.length];
      for (int i = 0; i < extensions.length; i++) {
        available[i] = i;
      }
      int ix = combo;
      for (int q = extensions.length; q > 0; --q) {
        int i = ix % q;
        ix = ix / q;
        int sel = available[i];
        // Replace the used extension with the last available extension
        available[i] = available[q - 1];
        available[q - 1] = -1;
        sb.append("-").append(extensions[sel]);
        selectedFilters[filterIx++] = filters[sel];
      }
      breakdownMap.put(sb.substring(1), selectedFilters);
    }
  }

  /**
   * @param breakdownName
   * @param files
   * @return all the groups
   */
  public List<Group> getGroups(String breakdownName, List<File> files) {
    List<Group> ret = new ArrayList<Group>();
    ExtensionFilter[] filters = breakdownMap.get(breakdownName);
    for (ExtensionFilter filter : filters) {
      List<File> groupFiles = new ArrayList<File>();
      for (File file : files) {
        if (filter.accept(file)) {
          groupFiles.add(file);
        }
      }
      ret.add(new Group(filter.extension, groupFiles));
    }
    return ret;
  }

}
