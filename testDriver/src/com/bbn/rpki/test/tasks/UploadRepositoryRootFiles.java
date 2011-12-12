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
 * A task to upload an entire repository root as a single operation.
 * There are two sub-tasks: delete deleted files and upload new or modified
 * files. 
 *
 * @author tomlinso
 */
public class UploadRepositoryRootFiles extends Task {
  
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
  public UploadRepositoryRootFiles(Model model, File repositoryRootDir) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<String> cmd = new ArrayList<String>();
    File rootDir = repositoryRootDir;
    cmd.add("scp");
    cmd.add("-qrB");
    for (File file : rootDir.listFiles()) {
      cmd.add(file.getPath());
    }
    String f = model.getSCPFileNameArg(rootDir, rootDir);
    cmd.add(f);
    String[] cmdArray = cmd.toArray(new String[cmd.size()]);
    Util.exec(cmdArray, "UploadRepositoryRoot", false, null, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 1;
  }

  /**
   * Break down this task into individual UploadNode tasks
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert n == 0;
    List<File> nodes = new ArrayList<File>();
    getNodes(nodes, repositoryRootDir);
    List<Task> tasks = new ArrayList<Task>(nodes.size());
    for (File node : nodes) {
      tasks.add(new MakeNodeDir(model, repositoryRootDir, node));
      tasks.add(new UploadNode(model, repositoryRootDir, node));
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
