/*
 * Created on Dec 10, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * A task to upload an entire repository root as a single operation
 *
 * @author tomlinso
 */
public class UploadRepositoryRoot implements Task {
  
  private static final FileFilter dirFilter = new FileFilter() {

    @Override
    public boolean accept(File f) {
      return f.isDirectory();
    }
  };
  
  private final File repositoryRootDir;
  
  private final Model model;

  /**
   * @param model
   * @param repositoryRootDir
   */
  public UploadRepositoryRoot(Model model, File repositoryRootDir) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run(int)
   */
  @Override
  public void run(int epochIndex) {
    List<String> cmd = new ArrayList<String>();
    File rootDir = repositoryRootDir;
    cmd.add("scp");
    cmd.add("-qr");
    for (File file : rootDir.listFiles()) {
      cmd.add(file.getPath());
    }
    String f = model.constructUploadRepositoryArg(rootDir, rootDir);
    cmd.add(f);
    String[] cmdArray = cmd.toArray(new String[cmd.size()]);
    Util.exec(cmdArray, "UploadRepositoryRoot", false, null, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount(int)
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 1;
  }

  /**
   * Break down this task into individual UploadNode tasks
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int, int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert n == 0;
    List<File> nodes = new ArrayList<File>();
    getNodes(nodes, repositoryRootDir);
    List<Task> tasks = new ArrayList<Task>(nodes.size());
    for (File node : nodes) {
      Task task = new UploadNode(model, repositoryRootDir, node);
      tasks.add(task);
    }
    return new TaskBreakdown(tasks, TaskBreakdown.Type.PARALLEL);
  }


  private void getNodes(List<File> nodes, File node) {
    nodes.add(node);
    File[] subdirs = node.listFiles(dirFilter);
    for (File subdir : subdirs) {
      getNodes(nodes, subdir);
    }
  }
}
