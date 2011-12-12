/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class DeleteFromRepositoryRoot extends Task {
  private final List<File> filesToDelete = new ArrayList<File>();
  private final Model model;
  private final File repositoryRootDir;

  /**
   * @param model
   * @param repositoryRootDir
   * @param previousRootDir 
   */
  public DeleteFromRepositoryRoot(Model model, File repositoryRootDir, File previousRootDir) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
    addFilesToDelete(repositoryRootDir, previousRootDir);
  }

  /**
   * @param thisDir
   * @param prevDir
   */
  private void addFilesToDelete(File thisDir, File prevDir) {
    Set<File> currentFiles = new HashSet<File>();
    currentFiles.addAll(Arrays.asList(prevDir.listFiles()));
    for (File file : thisDir.listFiles()) {
      File testFile = new File(prevDir, file.getName());
      if (currentFiles.contains(testFile)) {
        if (file.isDirectory()) {
          addFilesToDelete(file, testFile);
        }
      } else {
        filesToDelete.add(file);
      }
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<String> cmd = new ArrayList<String>();
    cmd.addAll(Arrays.asList("ssh", model.getServerName(repositoryRootDir), "rm", "-rf"));
    for (File file : filesToDelete) {
      String name = model.getUploadRepositoryFileName(repositoryRootDir, file);
      cmd.add(name);
    }
    Util.exec(cmd, "UploadRepositoryRootDelete", false, null, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 1;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    List<Task> tasks = new ArrayList<Task>();
    for (File file : filesToDelete) {
      addDeleteTask(tasks, file);
    }
    return new TaskBreakdown(tasks, TaskBreakdown.Type.SEQUENCE);
  }

  private void addDeleteTask(List<Task> tasks, File file) {
    if (file.isDirectory()) {
      for (File subfile : file.listFiles()) {
        addDeleteTask(tasks, subfile);
      }
    }
    String name = model.getUploadRepositoryFileName(repositoryRootDir, file);
    tasks.add(new DeleteRepositoryFile(model.getServerName(repositoryRootDir), name));
  }
}
