/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Task to upload one node
 * 
 * Can be broken down into individual UploadFile tasks for each file in the node
 *
 * @author tomlinso
 */
public class UploadNode extends Task {
  private static final FileFilter fileFilter = new FileFilter() {

    @Override
    public boolean accept(File f) {
      return f.isFile();
    }};
  
  private final File nodeDir;

  private final Model model;

  private final File repositoryRootDir;

  /**
   * @param model 
   * @param repositoryRootDir 
   * @param nodeDir 
   */
  public UploadNode(Model model, File repositoryRootDir, File nodeDir) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
    this.nodeDir = nodeDir;
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<String> cmd = new ArrayList<String>();
    String repository = model.getSCPFileNameArg(repositoryRootDir, nodeDir);
    cmd.add("scp");
    cmd.add("-qB");
    for (File file : nodeDir.listFiles(fileFilter)) {
      cmd.add(file.getPath());
    }
    cmd.add(repository);
    String[] cmdArray = cmd.toArray(new String[cmd.size()]);
    Util.exec(cmdArray, "UploadModel", false, Util.RPKI_ROOT, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 1;
  }

  /**
   * The one breakdown case we have is to upload individual files as separate,
   * parallel tasks
   * 
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert n == 0;
    List<Task> subtasks = new ArrayList<Task>();
    buildTasks(subtasks, nodeDir);
    return new TaskBreakdown(subtasks, TaskBreakdown.Type.PARALLEL);
  }

  private void buildTasks(List<Task> subtasks, File dir) {
    // A task for each file
    File[] files = dir.listFiles(fileFilter);
    for (File file : files) {
      subtasks.add(new UploadFile(model, repositoryRootDir, file));
    }
  }
  
  
}
