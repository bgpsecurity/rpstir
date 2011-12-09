/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.util.Arrays;
import java.util.Comparator;

/**
 * The test model is primarily held in a file system directory.
 * The model consists of a list of subdirectories specifying the
 * node hierarchy for the first and subsequent states of the
 * node hierarchy.
 *
 * @author tomlinso
 */
public class Model {

  /**
   * 
   */
  private static final String TAL_NAME = "test.tal";

  private static final FileFilter dirFilter = new FileFilter() {

    @Override
    public boolean accept(File file) {
      return file.isDirectory();
    }
  };

  private static final FilenameFilter cerFilter = new FilenameFilter() {

    @Override
    public boolean accept(File dir, String name) {
      return name.endsWith(".cer");
    }
  };
  
  private final File root;
  private final File modelDir;
  private final File[] epochDirs;

  /**
   * @param root
   * @param modelDir
   */
  public Model(File root, File modelDir) {
    this.root = root;
    this.modelDir = modelDir;
    epochDirs = modelDir.listFiles(dirFilter);
    Arrays.sort(epochDirs, new Comparator<File>() {

      @Override
      public int compare(File f1, File f2) {
        return f1.getName().compareTo(f2.getName());
      }
    });
  }
  
  /**
   * @return the root directory
   */
  public File getRoot() {
    return root;
  }
  
  /**
   * @return count o number of epochs
   */
  public int getEpochCount() {
    return epochDirs.length;
  }

  /**
   * @param n the index of the desired epoch
   * @return the modelDir
   */
  public File getEpochDir(int n) {
    return epochDirs[n];
  }

  /**
   * The trust anchor,for now is specified only once as the topmost SS cert
   * in the first topmost root.
   * @return the trust anchor cert file
   */
  public File getTrustAnchorCert() {
    File epochDir = getEpochDir(0);
    File[] certFiles = epochDir.listFiles(cerFilter);
    assert certFiles.length == 1;
    return certFiles[0];
  }

  /**
   * @return the TAL file
   */
  public File getTALFile() {
    return new File(getRoot(), TAL_NAME);
  }

  /**
   * @return
   */
  public String getRepository() {
    // TODO Auto-generated method stub
    return null;
  }

}
