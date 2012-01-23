/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Task to upload a repository root.
 * 
 * There are two breakdowns:
 *   deleteFirst has two subtasks to delete and upload in that order
 *   uploadFirst has two subtasks to upload and delete in that order
 *
 * @author tomlinso
 */
public class UploadRepositoryRoot extends Task {

  private final File repositoryRootDir;

  UploadRepositoryRoot(Model model, File repositoryRootDir) {
    super(repositoryRootDir.getName(), model);
    this.repositoryRootDir = repositoryRootDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(java.lang.String)
   */
  @Override
  protected TaskBreakdown getTaskBreakdown(String breakdownName) {
    if ("byNode".equals(breakdownName)) {
      List<Task> tasks = new ArrayList<Task>();
      for (File nodeDir :model.getNodeDirectories()) {
        File rootDir = model.getRootDirectory(nodeDir);
        if (rootDir.equals(repositoryRootDir)) {
          tasks.add(new UploadNode(model, nodeDir));
        }
      }
      return new TaskBreakdown(breakdownName, this, tasks);
    }
    if ("deleteFirst".equals(breakdownName)) {
      UploadRepositoryRootFiles uploadTask = new UploadRepositoryRootFiles(model, repositoryRootDir);
      DeleteFromRepositoryRoot deleteTask = new DeleteFromRepositoryRoot(model, repositoryRootDir);
      return new TaskBreakdown(breakdownName, this, deleteTask, uploadTask);
    }
    if ("updateFirst".equals(breakdownName)) {
      UploadRepositoryRootFiles uploadTask = new UploadRepositoryRootFiles(model, repositoryRootDir);
      DeleteFromRepositoryRoot deleteTask = new DeleteFromRepositoryRoot(model, repositoryRootDir);
      return new TaskBreakdown(breakdownName, this, uploadTask, deleteTask);
    }
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    new UploadRepositoryRootFiles(model, repositoryRootDir).run();
    new DeleteFromRepositoryRoot(model, repositoryRootDir).run();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return repositoryRootDir.getName();
  }
}
