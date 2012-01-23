/*
 * Created on Dec 10, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * A task to upload all the files of a repository root at once.
 * 
 * There are no breakdowns for this task.
 *
 * @author tomlinso
 */
public class UploadRepositoryRootFiles extends Task {

  private final File repositoryRootDir;

  /**
   * @return the repositoryRootDir
   */
  public File getRepositoryRootDir() {
    return repositoryRootDir;
  }

  private final File[] filesToUpload;

  /**
   * @param model
   * @param repositoryRootDir
   */
  public UploadRepositoryRootFiles(Model model, File repositoryRootDir) {
    super(repositoryRootDir.getParentFile().getName() + "/" + repositoryRootDir.getName(), model);
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
    String f = model.getSCPFileNameArg(repositoryRootDir);
    cmd.add(f);
    Util.exec("UploadRepositoryRoot", false, null, null, null, cmd);
  }

  /**
   * Break down this task into individual UploadNode tasks
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return filesToUpload.length + " files";
  }
}
