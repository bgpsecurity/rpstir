/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Constructor;
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
import java.util.TreeMap;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.ActionContext;
import com.bbn.rpki.test.actions.EpochEvent;
import com.bbn.rpki.test.actions.XMLConstants;
import com.bbn.rpki.test.objects.CA_Obj;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.Constants;
import com.bbn.rpki.test.objects.FactoryBase;
import com.bbn.rpki.test.objects.TestbedConfig;
import com.bbn.rpki.test.objects.TestbedCreate;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.objects.Util;

/**
 * Represents the current state of a test.
 * 
 * Test execution consists of a cycle:
 *    Update rpki objects according to the EpochEvents of actions.
 *    Uploading those updated objects.
 * 
 * The cache can be updated and validated at any point during the upload step
 * subject to the granularity of the breakdown of the upload.
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
public class Model implements Constants, XMLConstants {
  /**
   * Interface for listeners wanting to know when significant model changes have
   * occured. For now only the epochs collection can be monitored.
   *
   * @author tomlinso
   */
  public interface Listener {
    /**
     * Called when the epochs collection has changed
     */
    void epochsChanged();
  }

  static class TaskFactoryKey {
    private final Class<? extends TaskFactory> factoryClass;
    private final Object arg;
    /**
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((arg == null) ? 0 : arg.hashCode());
      result = prime * result + (factoryClass.hashCode());
      return result;
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
      TaskFactoryKey other = (TaskFactoryKey) obj;
      if (arg == null) {
        if (other.arg != null) {
          return false;
        }
      } else if (!arg.equals(other.arg)) {
        return false;
      }
      return factoryClass == other.factoryClass;
    }
    /**
     * @param factoryClass
     * @param arg
     */
    protected TaskFactoryKey(Class<? extends TaskFactory> factoryClass, Object arg) {
      super();
      this.factoryClass = factoryClass;
      this.arg = arg;
    }
  }
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
  private final List<AbstractAction> actions = new ArrayList<AbstractAction>();
  private final Set<EpochEvent> epochEvents = new HashSet<EpochEvent>();
  private final List<Epoch> epochs = new ArrayList<Epoch>();
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
  /**
   * @return the testbedConfig
   */
  public TestbedConfig getTestbedConfig() {
    return testbedConfig;
  }

  private final TypescriptLogger logger;
  protected Deque<TaskFactory.Task> tasks = new ArrayDeque<TaskFactory.Task>();
  private final Map<String, TaskFactory.Task> taskMap = new HashMap<String, TaskFactory.Task>();
  private final Map<TaskFactoryKey, TaskFactory> taskFactories = new HashMap<TaskFactoryKey, TaskFactory>();
  private final List<File> nodeDirectories = new ArrayList<File>();
  private final Map<String, File> nodeDirectoryByName = new TreeMap<String, File>();
  private final List<Listener> listeners = new ArrayList<Listener>(1);

  /**
   * @param rpkiRoot
   * @param iniFile
   * @param logger
   * @throws IOException
   */
  public Model(File rpkiRoot, String iniFile, TypescriptLogger logger) throws IOException {
    this.rpkiRoot = rpkiRoot;
    this.logger = logger;
    testbedConfig = new TestbedConfig(iniFile);
    TestbedCreate tbc = new TestbedCreate(testbedConfig);
    tbc.createDriver();
    iana = tbc.getRoot();
    iana.iterate(new CA_Object.IterationAction() {

      @Override
      public boolean performAction(CA_Object caObject) {
        File dir = new File(new File(REPO_PATH), caObject.SIA_path);
        nodeDirectories.add(dir);
        nodeDirectoryByName.put(caObject.getCommonName(), dir);
        return true;
      }
    });
    this.ianaServerName = testbedConfig.getFactory("IANA").getServerName();

    epochIndex = -1;

    addTask(getTaskFactory(InitializeCache.class).createOnlyTask());
    addTask(getTaskFactory(StartLoader.class).createOnlyTask());
    addTask(getTaskFactory(InitializeRepositories.class).createOnlyTask());
    addTask(getTaskFactory(AdvanceEpoch.class).createOnlyTask());
  }

  /**
   * @param file
   * @throws IOException
   */
  public void writeModel(File file) throws IOException {
    Element root = new Element("test-actions");
    Element iniFileElement = new Element(TAG_INI_FILE);
    StringWriter stringWriter = new StringWriter();
    testbedConfig.write(stringWriter);
    iniFileElement.addContent(stringWriter.toString());
    root.addContent(iniFileElement);
    ActionContext actionContext = new ActionContext();
    for (AbstractAction action : actions) {
      root.addContent(action.toXML(actionContext));
    }
    Document doc = new Document(root);
    XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
    Writer writer = new FileWriter(file);
    try {
      outputter.output(doc, writer);
    } finally {
      writer.close();
      writer = null;
    }
  }

  /**
   * @param l
   */
  public void addListener(Listener l) {
    listeners.add(l);
  }

  /**
   * @param l
   */
  public void removeListener(Listener l) {
    listeners.remove(l);
  }

  private void fireEpochsChanged() {
    for (Listener l : listeners) {
      l.epochsChanged();
    }
  }

  /**
   * @param <T>
   * @param cls
   * @return the TaskFactory for the specified class
   */
  public<T extends TaskFactory> T getTaskFactory(Class<T> cls) {
    return getTaskFactory(cls, null);
  }

  /**
   * @param <T>
   * @param cls
   * @param arg
   * @return the TaskFactory for the specified class
   */
  @SuppressWarnings("unchecked")
  public<T extends TaskFactory> T getTaskFactory(Class<T> cls, Object arg) {
    TaskFactoryKey key = new TaskFactoryKey(cls, arg);
    T ret = (T) taskFactories.get(key);
    if (ret == null) {
      try {
        if (arg == null) {
          Constructor<T> constructor = cls.getConstructor(Model.class);
          ret = constructor.newInstance(this);
        } else {
          Constructor<T> constructor = cls.getConstructor(Model.class, arg.getClass());
          ret = constructor.newInstance(this, arg);
        }
      } catch (Exception e) {
        if (e instanceof RuntimeException) {
          throw (RuntimeException) e;
        }
        throw new RuntimeException(e);
      }
      taskFactories.put(key, ret);
    }
    return ret;
  }

  /**
   * @param task
   */
  public void addTask(TaskFactory.Task task) {
    addTaskInner(task);
    if (shouldUpdateCache(task)) {
      addTaskInner(getTaskFactory(UpdateCache.class).createOnlyTask());
      addTaskInner(getTaskFactory(CheckCacheStatus.class).createOnlyTask());
    }
  }
  private void addTaskInner(TaskFactory.Task task) {
    tasks.add(task);
    Object old = taskMap.put(task.getTaskName(), task);
    assert old == null;
  }

  /**
   * @return the tasks of this test
   */
  public Iterable<TaskFactory.Task> getTasks() {
    return new Iterable<TaskFactory.Task>() {

      @Override
      public Iterator<TaskFactory.Task> iterator() {
        return new Iterator<TaskFactory.Task>() {
          TaskFactory.Task nextTask = null;

          @Override
          public boolean hasNext() {
            if (nextTask == null) {
              nextTask = nextTask();
            }
            return nextTask != null;
          }

          @Override
          public TaskFactory.Task next() {
            if (!hasNext()) {
              throw new NoSuchElementException();
            }
            TaskFactory.Task ret = nextTask;
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
  private TaskFactory.Task nextTask() {
    return tasks.poll();
  }

  /**
   * @param task
   * @return
   */
  protected boolean shouldUpdateCache(TaskFactory.Task task) {
    // Update the cache after each epoch, by default
    return task instanceof UploadEpoch.Task;
  }
  /**
   * @return all the server names
   */
  public Collection<String> getAllServerNames() {
    Set<String> ret = new HashSet<String>();
    for (FactoryBase factory : testbedConfig.getFactories().values()) {
      if (factory.isBreakAway()) {
        ret.add(factory.getServerName());
      }
    }
    ret.add(iana.getServerName());
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
    // Add this here so actions can operate on it.
    if (epochIndex == 0) {
      addTask(getTaskFactory(UploadTrustAnchors.class).createOnlyTask());
      addTaskInner(getTaskFactory(InstallTrustAnchor.class).createOnlyTask());
    }
    addTask(getTaskFactory(UploadEpoch.class).createOnlyTask());
    previousRepositoryRoots.clear();
    previousRepositoryRoots.addAll(repositoryRoots);
    repositoryRoots.clear();
    if (epochIndex <= 0) {
      // Epoch 0 actions are the building of the initial testbed
      // The results of which are ready to go.
    } else {
      Epoch epochActions = epochs.get(epochIndex - 1);
      for (EpochEvent epochEvent : epochActions.getEpochEvents()) {
        AbstractAction action = epochEvent.getAction();
        action.execute(null, logger);
      }
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
   * @return the list of EpochActions
   */
  public List<Epoch> getEpochs() {
    return epochs;
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
  public Collection<File> getRepositoryRoots() {
    if (repositoryRoots.isEmpty()) {
      // Use the configuration roots if empty
      return testbedConfig.getRepositoryRoots();
    }
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
  public TaskFactory.Task getTask(String string) {
    return taskMap.get(string);
  }

  /**
   * @return a list of the directories of all nodes
   */
  public List<File> getNodeDirectories() {
    return nodeDirectories;
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
        sb.append(".");
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

  /**
   * @param nodeName
   * @return the node directory corresponding to the node name
   */
  public File getNodeDirectory(String nodeName) {
    return nodeDirectoryByName.get(nodeName);
  }

  /**
   * @param repositoryRootName
   * @return the File corresponding to the named repository rooot
   */
  public File getRepositoryRoot(String repositoryRootName) {
    return new File(REPO_DIR, repositoryRootName);
  }

  /**
   * @return the names of the repository roots
   */
  public Collection<String> getRepositoryRootNames() {
    List<String> ret = new ArrayList<String>(repositoryRoots.size());
    for (File root : repositoryRoots) {
      String repositoryRootName = getRepositoryRootName(root);
      ret.add(repositoryRootName);
    }
    return ret;
  }

  /**
   * @param root
   * @return the name for the repository root
   */
  public String getRepositoryRootName(File root) {
    String serverName = root.getParentFile().getName();
    String rootName = root.getName();
    String repositoryRootName = serverName + "/" + rootName;
    return repositoryRootName;
  }

  /**
   * @return the top level tasks
   */
  public TaskFactory.Task[] getTopTasks() {
    UploadEpoch factory = getTaskFactory(UploadEpoch.class);
    TaskFactory.Task[] tasks = {
        factory.createOnlyTask()
    };
    return tasks;
  }

  /**
   * @return the Epochs
   */
  public Collection<EpochEvent> getEpochEvents() {
    return epochEvents;
  }

  /**
   */
  public void epochsChanged() {
    sortEpochs();
    fireEpochsChanged();
  }

  /**
   * Build a new array of EpochActions placing every action in the epoch
   * required by its constraints.
   * 
   * First the epoch constraint chains are searched to find epochs having no
   * predecessor constraints. Such epochs are assigned an index of zero. Other
   * epochs are assigned an index one greater than the max of all predecessor
   */
  private void sortEpochs() {
    Map<EpochEvent, AbstractAction> actionMap = new HashMap<EpochEvent, AbstractAction>();
    for (AbstractAction action : actions) {
      for (EpochEvent epochEvent : action.getAllEpochEvents()) {
        actionMap.put(epochEvent, action);
      }
    }
    epochEvents.clear();
    epochEvents.addAll(actionMap.keySet());
    EpochSorter sorter = new EpochSorter(epochEvents);
    epochs.clear();
    epochs.addAll(sorter.sort());
  }

  /**
   * Find the Epochs that can be successors of the given Epoch.
   * This set is all epochs that are not already constrained to be coincident
   * with or predecessors of the given epoch and that are not already constrained to be successors
   * @param epoch
   * @return the epochs that are not already constrained w.r.t. the given epoch
   */
  public Collection<EpochEvent> getPossibleSuccessors(EpochEvent epoch) {
    Set<EpochEvent> ret = new HashSet<EpochEvent>(epochEvents);
    ret.remove(epoch);
    ret.removeAll(epoch.getSuccessorEpochEvents());
    ret.removeAll(epoch.findCoincidentEpochs());
    ret.removeAll(epoch.findPredecessorEpochs());
    return ret;
  }

  /**
   * Find the Epochs that can be predecessors of the given Epoch.
   * This set is all epochs that are not already constrained to be coincident
   * with of succcessors of the given epoch and that are not already constrained to be predecessors.
   * @param epoch
   * @return the epochs that are not already constrained w.r.t. the given epoch
   */
  public Collection<EpochEvent> getPossiblePredecessors(EpochEvent epoch) {
    Set<EpochEvent> ret = new HashSet<EpochEvent>(epochEvents);
    ret.remove(epoch);
    ret.removeAll(epoch.getPredecessorEpochEvents());
    ret.removeAll(epoch.findCoincidentEpochs());
    ret.removeAll(epoch.findSuccessorEpochs());
    return ret;
  }

  /**
   * Find the Epochs that can be coincident with the given Epoch.
   * This set is all epochs that are not already constrained to be successors of
   * or predecessors of the given epoch and that are not already constrained to be coincident
   * @param epoch
   * @return the epochs that are not already constrained w.r.t. the given epoch
   */
  public Collection<EpochEvent> getPossibleCoincidentEpochs(EpochEvent epoch) {
    Set<EpochEvent> ret = new HashSet<EpochEvent>(epochEvents);
    ret.remove(epoch);
    ret.removeAll(epoch.getCoincidentEpochs());
    ret.removeAll(epoch.findSuccessorEpochs());
    ret.removeAll(epoch.findPredecessorEpochs());
    return ret;
  }

  /**
   * @param action
   */
  public void addAction(AbstractAction action) {
    actions.add(action);
    epochsChanged();
  }

  /**
   * @param action the action to remove
   */
  public void removeAction(AbstractAction action) {
    actions.remove(action);
    epochsChanged();
  }
}
