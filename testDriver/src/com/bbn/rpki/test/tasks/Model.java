/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.bbn.rpki.test.objects.TestbedConfig;

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

  private static final FileFilter epochDirFilter = new FileFilter() {
    private final Matcher matcher = Pattern.compile("epoch_\\d\\d\\d").matcher("");

    @Override
    public boolean accept(File file) {
      return file.isDirectory() && matcher.reset(file.getName()).matches();
    }
  };

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

  private final File rpkiRoot;
  private final File[] epochDirs;

  private String ianaServerName;

  /**
   * @param root
   * @param modelDir
   * @throws IOException 
   */
  public Model(File rpkiRoot, File modelDir) throws IOException {
    this.rpkiRoot = rpkiRoot;
    TestbedConfig testbedConfig = new TestbedConfig(new File(modelDir, "model.ini"));
    this.ianaServerName = testbedConfig.getFactory("IANA").getServerName();
    epochDirs = modelDir.listFiles(epochDirFilter);
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
  public File getRPKIRoot() {
    return rpkiRoot;
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
    File epochDir = new File(getEpochDir(0), ianaServerName);
    File[] certFiles = epochDir.listFiles(cerFilter);
    assert certFiles.length == 1;
    return certFiles[0];
  }

  /**
   * @return the TAL file
   */
  public File getTALFile() {
    return new File(getRPKIRoot(), TAL_NAME);
  }
  
  /**
   * @return the rsync url of the top-most node
   */
  public String getTrustAnchorURL() {
    // TODO need a positive way to determine where trust anchors are
    File epoch0Dir = getEpochDir(0);
    return String.format("rsync://%s", ianaServerName);
  }

  /**
   * @param epochIndex
   * @return the repository root files
   */
  public List<File> getRepositoryRoots(int epochIndex) {
    List<File> files = new ArrayList<File>();
    for (File serverDir : getEpochDir(epochIndex).listFiles(dirFilter)) {
      files.addAll(Arrays.asList(serverDir.listFiles(dirFilter)));
    }
    return files;
  }

  /**
   * @param repositoryRootDir a root
   * @param nodeDir a node at or under the root
   * @return scp target for the node
   */
  public String constructUploadRepositoryArg(File repositoryRootDir, File nodeDir) {
    // TODO Because I want to upload using scp, I need to know how each rsync
    // server is set up.
    // For now assume roots are sub-directories of /home/rsync
    File rootDir = repositoryRootDir;
    String moduleName = rootDir.getName();
    String serverName = rootDir.getParentFile().getName();
    String rootPath = rootDir.getPath();
    String nodePath = nodeDir.getPath();
    assert nodePath.startsWith(rootPath);
    assert rootPath.endsWith("/");
    String nodeTail = nodePath.substring(rootPath.length());
    return String.format("%s:/home/rsync/%s/%s", serverName, moduleName, nodeTail);
  }
}
