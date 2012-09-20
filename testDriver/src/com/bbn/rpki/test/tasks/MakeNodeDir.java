/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Task to create the directory for one node
 *
 * @author tomlinso
 */
public class MakeNodeDir extends TaskFactory {
  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task(File nodeDir) {
      super("MakeNodeDir");
      this.nodeDir = nodeDir;
    }

    private final File nodeDir;

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
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
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

  /**
   * @param model
   */
  public MakeNodeDir(Model model) {
    super(model);
  }

  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // No breakdowns
  }

  @Override
  protected Task reallyCreateTask(String nodeName) {
    return new Task(model.getNodeDirectory(nodeName));
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    List<String> ret = new ArrayList<String>();
    for (File nodeDir : model.getNodeDirectories()) {
      String nodeName = model.getNodeName(nodeDir);
      ret.add(nodeName);
    }
    return ret;
  }
}
