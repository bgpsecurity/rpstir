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

  /**
   * @param model
   * @param nodeDir
   */
  public MakeNodeDir(Model model, File nodeDir) {
    super("MakeNodeDir", model);
    this.nodeDir = nodeDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    String[] sourceParts = model.getSourcePath(nodeDir);
    List<String> cmd = new ArrayList<String>();
    String serverName = sourceParts[0];
    String rootName = sourceParts[1];
    StringBuilder sb = new StringBuilder(model.getRsyncBase(serverName, rootName));
    for (int i = 2; i < sourceParts.length; i++) {
      if (i > 2) {
        sb.append("/");
      }
      sb.append(sourceParts[i]);
    }
    cmd.add("ssh");
    cmd.add(serverName);
    cmd.add("mkdir");
    cmd.add("-p");
    cmd.add(sb.toString());
    Util.exec("Make remote dir", false, null, null, null, cmd);
  }

  /**
   * The one breakdown case we have is to upload individual files as separate,
   * parallel tasks
   * 
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    // No breakdowns
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    String[] sourceParts = model.getSourcePath(nodeDir);
    String serverName = sourceParts[0];
    StringBuilder sb = new StringBuilder();
    for (int i = 1; i < sourceParts.length; i++) {
      if (i > 1) {
        sb.append("/");
      }
      sb.append(sourceParts[i]);
    }
    return String.format("%s on %s", sb.toString(), serverName);
  }
}
