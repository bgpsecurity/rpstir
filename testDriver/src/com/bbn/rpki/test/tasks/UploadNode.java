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
public class UploadNode implements Task {
  private static final FileFilter fileFilter = new FileFilter() {

    @Override
    public boolean accept(File f) {
      return f.isFile();
    }};
  
  private final File nodeDir;
  private final String repository;

  /**
   * @param modelDir
   * @param repository
   */
  public UploadNode(File modelDir, String repository) {
    this.repository = repository;
    this.nodeDir = modelDir.getAbsoluteFile();
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
    List<String> cmd = new ArrayList<String>();
    cmd.add("scp");
    cmd.add("-q");
    for (File file : nodeDir.listFiles(fileFilter)) {
      cmd.add(file.getPath());
    }
    cmd.add(repository);
    String[] cmdArray = cmd.toArray(new String[cmd.size()]);
    Util.exec(cmdArray, "UploadModel", false, Util.RPKI_ROOT);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 1;
  }

  /**
   * The one breakdown case we have is to upload individual files as separate,
   * parallel tasks
   * 
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert n == 0;
    List<Task> subtasks = new ArrayList<Task>();
    buildTasks(subtasks, nodeDir, repository);
    return new TaskBreakdown(subtasks, TaskBreakdown.Type.PARALLEL);
  }

  private void buildTasks(List<Task> subtasks, File dir, String repository) {
    // A task for each file
    File[] files = dir.listFiles(fileFilter);
    for (File file : files) {
      subtasks.add(new UploadFile(file, repository));
    }
  }
  
  
}
