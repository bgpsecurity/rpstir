/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ExtensionHandler {

  public static class ExtensionFilter implements FileFilter {
    private final String extension;
    ExtensionFilter(String extension) {
      this.extension = extension;
    }

    @Override
    public boolean accept(File file) {
      return file.getName().endsWith("." + extension);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
      return extension.hashCode();
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      ExtensionFilter other = (ExtensionFilter) obj;
      return extension.equals(other.extension);
    }

    /**
     * @return
     */
    public String getExtension() {
      return extension;
    }
  }

  /**
   * The extensions for file groups
   */
  public static String[] extensions = {
    "cer",
    "mft",
    "crl",
    "roa",
  };

  private final Map<String, ExtensionFilter[]> breakdownMap = new TreeMap<String, ExtensionFilter[]>();

  /**
   * Constructor
   */
  public ExtensionHandler() {
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
   * @return the names of the possible breakdowns
   */
  public Collection<String> getBreakdownNames() {
    return breakdownMap.keySet();
  }

  /**
   * @param breakdownName
   * @return
   */
  public ExtensionFilter[] getExtensionFilter(String breakdownName) {
    return breakdownMap.get(breakdownName);
  }
}
