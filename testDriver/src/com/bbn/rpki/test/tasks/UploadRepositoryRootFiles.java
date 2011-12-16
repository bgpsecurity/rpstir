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

  private static final FileFilter fileFilter = new FileFilter() {

    @Override
    public boolean accept(File f) {
      return f.isFile();
    }
  };
  
  private final File repositoryRootDir;
  
  /**
   * @return the repositoryRootDir
   */
  public File getRepositoryRootDir() {
    return repositoryRootDir;
  }


  private final Model model;

  private File[] filesToUpload;

  /**
   * @param model
   * @param repositoryRootDir
   */
  public UploadRepositoryRootFiles(Model model, File repositoryRootDir) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
    filesToUpload = repositoryRootDir.listFiles();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<String> cmd = new ArrayList<String>();
    cmd.add("scp");
    cmd.add("-qrB");
    for (File file : filesToUpload) {
      cmd.add(file.getPath());
    }
    String f = model.getSCPFileNameArg(repositoryRootDir, repositoryRootDir);
    cmd.add(f);
    Util.exec("UploadRepositoryRoot", false, null, null, null, cmd);
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
    File[] topFiles = repositoryRootDir.listFiles(fileFilter);
    List<Task> tasks = new ArrayList<Task>(nodes.size() + topFiles.length);
    for (File file : topFiles) {
      tasks.add(new UploadFile(model, repositoryRootDir, file));
    }
    for (File node : nodes) {
      tasks.add(new MakeNodeDir(model, repositoryRootDir, node));
      tasks.add(new UploadNode(model, repositoryRootDir, node));
    }
    return new TaskBreakdown(tasks, TaskBreakdown.Type.PARALLEL);
  }


  private void getNodes(List<File> nodes, File parent) {
    File[] nodeDirs = parent.listFiles(dirFilter);
    for (File nodeDir : nodeDirs) {
      nodes.add(nodeDir);
      getNodes(nodes, nodeDir);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return filesToUpload.length + " files";
  }
}
