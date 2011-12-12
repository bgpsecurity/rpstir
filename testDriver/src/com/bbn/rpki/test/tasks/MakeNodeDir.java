/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
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
public class MakeNodeDir extends Task {
  private final File nodeDir;

  private final Model model;

  private final File repositoryRootDir;

  /**
   * @param model 
   * @param repositoryRootDir 
   * @param nodeDir 
   */
  public MakeNodeDir(Model model, File repositoryRootDir, File nodeDir) {
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
    String repository = model.getUploadRepositoryFileName(repositoryRootDir, nodeDir);
    String serverName = model.getServerName(repositoryRootDir);
    cmd.add("ssh");
    cmd.add(serverName);
    cmd.add("mkdir");
    cmd.add("-p");
    cmd.add(repository);
    Util.exec(cmd, "Make remote dir", false, null, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 0;
  }

  /**
   * The one breakdown case we have is to upload individual files as separate,
   * parallel tasks
   * 
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert false;
    return null;
  }
}
