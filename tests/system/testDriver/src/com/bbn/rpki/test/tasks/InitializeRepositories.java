/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class InitializeRepositories extends TaskFactory {

  private static final String TASK_NAME = "InitializeRepositories";

  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task() {
      super(TASK_NAME);
    }

    @Override
    public void run() {
      for (String serverName : model.getAllServerNames()) {
        String[] sourceParts = serverName.split("/");
        String remotePath = model.getRemotePath(sourceParts);
        if (!remotePath.endsWith("/")) {
          remotePath += "/";
        }
        Util.exec("Initialize Repository", false, false, null,
                  null,
                  null,
                  "ssh",
                  sourceParts[0],
                  "rm",
                  "-rf", remotePath + "*");
      }
      for (File nodeDir : model.getNodeDirectories()) {
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
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return null;
    }

  }

  /**
   * @param model
   */
  public InitializeRepositories(Model model) {
    super(model);
  }

  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There no breakdowns
  }

  @Override
  protected Task reallyCreateTask(String arg) {
    assert TASK_NAME.equals(arg);
    return new Task();
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    return Collections.singleton(TASK_NAME);
  }
}
