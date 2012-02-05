/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.AllocateAction;
import com.bbn.rpki.test.actions.ChooseCacheCheckTask;
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
 * Represents the current state of a test.
 * 
 * Test execution consists of a cycle of generating updates for the rpki objects
 * (files) and uploading those updated objects. The cache can be updated and
 * validated can occur at any point during the upload step subject to the
 * granularity of the breakdown of the upload.
 * 
 * The cycle can be tailoring in three ways: specifying what changes should be
 * made to the rpki objects, how the upload process should be broken down and
 * where within the breakdown cache update and validation should occur. The last
 * two are combined into a single concept by specifying the path to a particular
 * breakdown task after which cache update/validation should occur. The path
 * consists of a sequence of alternating task and breakdown names. For example:
 *     UploadEpoch:byRepositoryRoot:rpki.bbn.com/rst:deleteFirst:upload:
 *
 * @author tomlinso
 */
public class Model implements Constants {

  static final File REPO_DIR = new File(REPO_PATH);
  private static final String TAL_NAME = "test.tal";
  private static final String FILE_SEP = System.getProperty("file.separator", "/");

  private static final FilenameFilter cerFilter = new FilenameFilter() {

    @Override
    public boolean accept(File dir, String name) {
      return name.endsWith(".cer");
    }
  };

  private static final FileFilter dirFilter = new FileFilter() {

    @Override
    public boolean accept(File file) {
      return file.isDirectory();
    }
  };

  private final File rpkiRoot;

  private final List<EpochActions> epochs = new ArrayList<EpochActions>();

  private final String ianaServerName;

  private final CA_Object iana;
  private final List<File> objectList = new ArrayList<File>();
  private final List<File> writtenFiles = new ArrayList<File>();
  private final List<File> supercededFiles = new ArrayList<File>();
  private final List<File> untouchedFiles = new ArrayList<File>();
  private int epochIndex;
  private final List<File> repositoryRoots = new ArrayList<File>();
  private final List<File> previousRepositoryRoots = new ArrayList<File>();
  private final TestbedConfig testbedConfig;
  private final TypescriptLogger logger;
  protected Deque<Task> tasks = new ArrayDeque<Task>();
  private final Map<String, Task> taskMap = new HashMap<String, Task>();

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
    String path = "UploadEpoch:byNode:IANA-0/RIPE-2/LIR-3:deleteFirst:upload(IANA-0/RIPE-2/LIR-3):cer-mft-roa-crl:cer";
    AbstractAction action2 = new ChooseCacheCheckTask(this, path);
    EpochActions epochActions = new EpochActions(0, action1, action2);
    epochs.add(epochActions);
    epochIndex = -1;

    Element root = new Element("test-actions");
    root.addContent(epochActions.toXML());
    Document doc = new Document(root);
    XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
    outputter.output(doc, System.out);
    addTask(new InitializeCache(this));
    addTask(new StartLoader(this));
    addTask(new InitializeRepositories(this));
    addTask(new AdvanceEpoch(this));
  }

  /**
   * @param task
   */
  public void addTask(Task task) {
    addTaskInner(task);
    if (shouldInstallTrustAnchor(task, getEpochIndex())) {
      addTaskInner(new InstallTrustAnchor(this));
    }
    if (shouldUpdateCache(task)) {
      addTaskInner(new UpdateCache(this));
      addTaskInner(new CheckCacheStatus(this));
    }
  }
  private void addTaskInner(Task task) {
    tasks.add(task);
    Object old = taskMap.put(task.getTaskName(), task);
    assert old == null;
  }

  /**
   * @return the tasks of this test
   */
  public Iterable<Task> getTasks() {
    return new Iterable<Task>() {

      @Override
      public Iterator<Task> iterator() {
        return new Iterator<Task>() {
          Task nextTask = null;

          @Override
          public boolean hasNext() {
            if (nextTask == null) {
              nextTask = nextTask();
            }
            return nextTask != null;
          }

          @Override
          public Task next() {
            if (!hasNext()) {
              throw new NoSuchElementException();
            }
            Task ret = nextTask;
            taskMap.remove(ret.getTaskName());
            nextTask = null;
            return ret;
          }

          @Override
          public void remove() {
            throw new UnsupportedOperationException();
          }
        };
      }
    };
  }

  /**
   * @return the next Task or null if finished
   */
  private Task nextTask() {
    return tasks.poll();
  }

  /**
   * @param task
   * @return
   */
  private boolean shouldInstallTrustAnchor(Task task, int epochIndex) {
    if (epochIndex == 0) {
      // For not only install trust anchors for epoch 0
      // Upload just after uploading an entire epoch (if not broken down)
      if (task instanceof UploadEpoch) {
        return true;
      }
      // Upload just after uploading any root (only trust anchors within)
      if (task instanceof UploadRepositoryRoot) {
        UploadRepositoryRootFiles urr = (UploadRepositoryRootFiles) task;
        File[] topFiles = urr.getRepositoryRootDir().listFiles(cerFilter);
        return topFiles.length > 0;
      }
      if (task instanceof UploadFile) {
        UploadFile uploadFileTask = (UploadFile) task;
        File file = uploadFileTask.getFile();
        String[] path = getSourcePath(file);
        File rootDir = new File(new File(REPO_DIR, path[0]), path[1]);
        return file.getParentFile().equals(rootDir) && file.getName().endsWith(".cer");
      }
    }
    return false;
  }

  /**
   * @param task
   * @return
   */
  protected boolean shouldUpdateCache(Task task) {
    // Update the cache after each epoch, by default
    return task instanceof UploadEpoch;
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
   * Advance to the next epoch.
   * 
   * 1) Record the previous roots so UploadEpoch can know what already exists
   *    when breaking down the upload into uploading each root.
   * 2) Apply all the actions of the epoch.
   * 3) Build the list of all the objects of the new epoch.
   * 4) Determine which of the objects are newly written, untouched, or
   *    superceded (deleted).
   * 5) Finally, determine the new set of roots.
   */
  public void advanceEpoch() {
    ++epochIndex;
    addTask(new UploadEpoch(this));
    previousRepositoryRoots.clear();
    previousRepositoryRoots.addAll(repositoryRoots);
    repositoryRoots.clear();
    if (epochIndex > 0) {
      EpochActions epochActions = epochs.get(epochIndex - 1);
      epochActions.execute(logger);
    }
    Set<File> previousFiles = new HashSet<File>(objectList);
    objectList.clear();
    List<CA_Obj> objects = new ArrayList<CA_Obj>();
    iana.appendObjectsToWrite(objects);
    writtenFiles.clear();
    supercededFiles.clear();
    untouchedFiles.clear();
    for (int i = 0; i < objects.size(); i++) {
      CA_Obj ca_Obj = objects.get(i);
      if (!ca_Obj.isWritten()) {
        Util.writeConfig(ca_Obj);
        Util.create_binary(ca_Obj);
        ca_Obj.setWritten(true);
        writtenFiles.add(new File(ca_Obj.outputfilename));
      } else {
        untouchedFiles.add(new File(ca_Obj.outputfilename));
      }
      objectList.add(new File(ca_Obj.outputfilename));
    }
    previousFiles.removeAll(objectList);
    for (File file : previousFiles) {
      file.delete();
      supercededFiles.add(file);
    }
    for (File serverFile : REPO_DIR.listFiles(dirFilter)) {
      if (serverFile.getName().equals("EE")) {
        continue;
      }
      repositoryRoots.addAll(Arrays.asList(serverFile.listFiles(dirFilter)));
    }
  }

  /**
   * @return the root directory
   */
  public File getRPKIRoot() {
    return rpkiRoot;
  }

  /**
   * @return count of number of epochs
   */
  public int getEpochCount() {
    return epochs.size() + 1;
  }

  /**
   * @param epochIndex
   * @return
   */
  public EpochActions getEpochActions(int epochIndex) {
    return epochs.get(epochIndex - 1);
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
   * @param publicationSource
   * @return get the path of a publicationSource relative to the
   * source repository directory broken into parts
   */
  public String[] getSourcePath(File publicationSource) {
    String path = publicationSource.getPath();
    String repo = REPO_PATH;
    String repoRelativePath1 = path.substring(repo.length());
    String repoRelativePath = repoRelativePath1;
    return repoRelativePath.split(FILE_SEP);
  }

  /**
   * @param serverName
   * @param rootName
   * @return the path to the given rootName on the given rsync server
   */
  public String getRsyncBase(String serverName, String rootName) {
    // For now assume roots are sub-directories of /home/rsync
    return "/home/rsync/" + rootName + "/";
  }

  /**
   * Get an scp argument for a remote file
   * @param file
   * @return the scp argument
   */
  public String getSCPFileNameArg(File file) {
    String[] sourcePath = getSourcePath(file);
    String serverName = sourcePath[0];
    String remotePath = getRemotePath(sourcePath);
    return serverName + ":" + remotePath;
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

  /**
   * @return the list of superceded files
   */
  public List<File> getSupercededFiles() {
    return supercededFiles;
  }

  /**
   * @return the list of writtenFiles
   */
  public List<File> getWrittenFiles() {
    return writtenFiles;
  }

  /**
   * @return all the changed rpki objects (files)
   */
  public Collection<File> getChangedPublicationSources() {
    Set<File> ret = new HashSet<File>();
    for (File file : getWrittenFiles()) {
      ret.add(file.getParentFile());
    }
    for (File file : getSupercededFiles()) {
      ret.add(file.getParentFile());
    }
    for (File file : getWrittenFiles()) {
      ret.add(file.getParentFile());
    }
    return ret;
  }

  /**
   * @param string
   * @return the task with the given name
   */
  public Task getTask(String string) {
    return taskMap.get(string);
  }

  /**
   * @return a list of the directories of all nodes
   */
  public List<File> getNodeDirectories() {
    List<File> ret = new ArrayList<File>();
    iana.appendNodeDirectories(ret);
    return ret;
  }

  /**
   * @param nodeDir
   * @return the directory of the root containing the node
   */
  public File getRootDirectory(File nodeDir) {
    String[] sourcePath = getSourcePath(nodeDir);
    return new File(new File(Model.REPO_DIR, sourcePath[0]), sourcePath[1]);
  }

  /**
   * @param nodeDir
   * @return the fully-qualified name of the node
   */
  public String getNodeName(File nodeDir) {
    String[] sourcePath = getSourcePath(nodeDir);
    StringBuilder sb = new StringBuilder();
    for (int i = 2; i < sourcePath.length; i++) {
      if (i > 2) {
        sb.append("/");
      }
      sb.append(sourcePath[i]);
    }
    return sb.toString();
  }

  /**
   * @param sourceParts
   * @return the path on the remote rsync server
   */
  public String getRemotePath(String[] sourceParts) {
    String serverName = sourceParts[0];
    String rootName = sourceParts[1];
    StringBuilder sb = new StringBuilder(getRsyncBase(serverName, rootName));
    for (int i = 2; i < sourceParts.length; i++) {
      if (i > 2) {
        sb.append("/");
      }
      sb.append(sourceParts[i]);
    }
    return sb.toString();
  }

  /**
   * @return the root CA
   * TODO local trust anchors mean multiple roots.
   */
  public CA_Object getRootCA() {
    return iana;
  }
}
