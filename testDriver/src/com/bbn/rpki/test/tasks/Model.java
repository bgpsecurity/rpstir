/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.AllocateAction;
import com.bbn.rpki.test.actions.EpochActions;
import com.bbn.rpki.test.objects.CA_Obj;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.Constants;
import com.bbn.rpki.test.objects.FactoryBase;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.TestbedConfig;
import com.bbn.rpki.test.objects.TestbedCreate;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.objects.Util;

/**
 * The test model is primarily held in a file system directory.
 * The model consists of a list of subdirectories specifying the
 * node hierarchy for the first and subsequent states of the
 * node hierarchy.
 *
 * @author tomlinso
 */
public class Model implements Constants {

  private static final File REPO_DIR = new File(REPO_PATH);
  private static final String TAL_NAME = "test.tal";

  private static final FilenameFilter cerFilter = new FilenameFilter() {

    @Override
    public boolean accept(File dir, String name) {
      return name.endsWith(".cer");
    }
  };

  private final File rpkiRoot;

  private final List<EpochActions> epochs = new ArrayList<EpochActions>();

  private final String ianaServerName;

  private final CA_Object iana;
  private final List<String> objectList = new ArrayList<String>();
  private int epochIndex;
  private final List<File> repositoryRoots = new ArrayList<File>();
  private final List<File> previousRepositoryRoots = new ArrayList<File>();
  private final TestbedConfig testbedConfig;
  private final TypescriptLogger logger;

  /**
   * @param rpkiRoot
   * @param iniFile
   * @param logger 
   * @throws IOException
   */
  public Model(File rpkiRoot, File iniFile, TypescriptLogger logger) throws IOException {
    this.rpkiRoot = rpkiRoot;
    this.logger = logger;
    testbedConfig = new TestbedConfig(iniFile);
    TestbedCreate tbc = new TestbedCreate(testbedConfig);
    tbc.createDriver();
    iana = tbc.getRoot();
    this.ianaServerName = testbedConfig.getFactory("IANA").getServerName();

    // Build some actions
    CA_Object ripe = iana.findNode("RIPE-2");
    CA_Object lir1 = ripe.findNode("LIR-2");
    AbstractAction action1 = new AllocateAction(ripe, lir1, "a1", IPRangeType.ipv4, new Pair("p", 8));
    EpochActions epochActions = new EpochActions(0, action1);
    epochs.add(epochActions);
    epochIndex = -1;

    Element root = new Element("test-actions");
    root.addContent(epochActions.toXML());
    Document doc = new Document(root);
    XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
    outputter.output(doc, System.out);
  }

  /**
   * @return all the server names
   */
  public Collection<String> getAllServerNames() {
    Set<String> ret = new HashSet<String>();
    for (FactoryBase factory : testbedConfig.getFactories().values()) {
      if (factory.isBreakAway() || factory == iana.myFactory) {
        ret.add(factory.getServerName());
      }
    }
    return ret;
  }

  /**
   * @return the current list of objects
   */
  public List<String> getObjectList() {
    return objectList;
  }

  /**
   * Advance to the next epoch -- copy the current object list to the previous
   * object list. Apply the actions of the epoch and record the new current
   * object list.
   */
  public void advanceEpoch() {
    List<String> previousFiles = new ArrayList<String>(objectList);
    objectList.clear();

    previousRepositoryRoots.clear();
    previousRepositoryRoots.addAll(repositoryRoots);
    repositoryRoots.clear();
    if (++epochIndex > 0) {
      EpochActions epochActions = epochs.get(epochIndex - 1);
      epochActions.execute(logger);
    }
    List<CA_Obj> objects = new ArrayList<CA_Obj>();
    iana.appendObjectsToWrite(objects);
    for (int i = 0; i < objects.size(); i++) {
      CA_Obj ca_Obj = objects.get(i);
      if (!ca_Obj.isWritten()) {
        Util.writeConfig(ca_Obj);
        Util.create_binary(ca_Obj);
        ca_Obj.setWritten(true);
      }
      objectList.add(ca_Obj.outputfilename);
    }
    previousFiles.removeAll(objectList);
    for (String file : previousFiles) {
      new File(file).delete();
    }
    List<CA_Object> nodes = new ArrayList<CA_Object>();
    iana.appendRoots(nodes);
    for (CA_Object node : nodes) {
      repositoryRoots.add(new File(Constants.REPO_PATH, node.SIA_path));
    }
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
    return epochs.size() + 1;
  }

  /**
   * The trust anchor,for now is specified only once as the topmost SS cert
   * in the first topmost root.
   * @return the trust anchor cert file
   */
  public File getTrustAnchorCert() {
    File epochDir = new File(REPO_DIR, ianaServerName);
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
    return String.format("rsync://%s", ianaServerName);
  }

  /**
   * @return the repository root files
   */
  public List<File> getRepositoryRoots() {
    return repositoryRoots;
  }

  /**
   * @return the repository root files
   */
  public List<File> getPreviousRepositoryRoots() {
    return previousRepositoryRoots;
  }

  /**
   * @param repositoryRootDir
   * @return the server name for the specified root
   */
  public String getServerName(File repositoryRootDir) {
    return repositoryRootDir.getParentFile().getName();
  }

  /**
   * Get the name of a file on a server
   * The name does not include any servername prefix
   * 
   * @param repositoryRootDir a root
   * @param nodeDir a node at or under the root
   * @return target filename for the node
   */
  public String getUploadRepositoryFileName(File repositoryRootDir, File nodeDir) {
    File rootDir = repositoryRootDir;
    String serverHostName = rootDir.getParentFile().getName();
    String moduleName = rootDir.getName();
    String serverName = serverHostName + "/" + moduleName;
    String rootPath = rootDir.getPath();
    String nodePath = nodeDir.getPath();
    assert nodePath.startsWith(rootPath);
    assert !rootPath.endsWith("/");
    String nodeTail = nodePath.substring(rootPath.length());
    String ret = getRsyncBase(serverName) + nodeTail;
    return ret;
  }

  /**
   * @param serverName
   * @return the directory on the rsync server named by serverName
   */
  public String getRsyncBase(String serverName) {
    // TODO Because I want to upload using scp, I need to know how each rsync
    // server is set up.
    // For now assume roots are sub-directories of /home/rsync
    String[] parts = serverName.split("/");
    assert parts.length == 2;
    String moduleName = parts[1];
    return "/home/rsync/" + moduleName + "/";
  }

  /**
   * Get an scp argument for a remote file
   * @param repositoryRootDir
   * @param file
   * @return the scp argument
   */
  public String getSCPFileNameArg(File repositoryRootDir, File file) {
    String serverName = getServerName(repositoryRootDir);
    String remoteFileName = getUploadRepositoryFileName(repositoryRootDir, file);
    return serverName + ":" + remoteFileName;
  }

  /**
   * @param file
   */
  public void uploadedFile(File file) {
    // TODO Auto-generated method stub

  }

  /**
   * @param filesToDelete
   */
  public void deletedFiles(List<File> filesToDelete) {
    // TODO Auto-generated method stub

  }

  /**
   * @param file
   */
  public void deletedFile(File file) {
    // TODO Auto-generated method stub

  }

  /**
   * @param certFile
   */
  public void addTrustAnchor(File certFile) {
    // TODO Auto-generated method stub

  }

  /**
   * @param filesToUpload
   */
  public void uploadedFiles(List<File> filesToUpload) {
    // TODO Auto-generated method stub

  }

  /**
   * 
   */
  public void clearDatabase() {
    // TODO Auto-generated method stub

  }

  /**
   * @return the epochIndex
   */
  public int getEpochIndex() {
    return epochIndex;
  }
}
