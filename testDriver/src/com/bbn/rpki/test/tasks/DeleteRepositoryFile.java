/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;

import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class DeleteRepositoryFile extends Task {

  private final File repositoryRootDir;
  private final File file;
  private final Model model;

  /**
   * @param model 
   * @param repositoryRootDir 
   * @param file 
   */
  public DeleteRepositoryFile(Model model, File repositoryRootDir, File file) {
    this.model = model;
    this.repositoryRootDir = repositoryRootDir;
    this.file = file;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    String serverName = model.getServerName(repositoryRootDir);
    String name = model.getUploadRepositoryFileName(repositoryRootDir, file);
    Util.exec("DeleteRepositoryFile", false, null, null,
              null,
              "ssh",
              serverName,
              "rm",
              "-rf", name
    );
    model.deletedFile(file);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert false;
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    String serverName = model.getServerName(repositoryRootDir);
    String name = model.getUploadRepositoryFileName(repositoryRootDir, file);
    return String.format("%s from %s", name, serverName);
  }
}
