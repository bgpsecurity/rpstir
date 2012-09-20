/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

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
        Util.exec("Initialize Repository", false, null, null,
                  null,
                  "ssh",
                  sourceParts[0],
                  "rm",
                  "-rf",
                  remotePath + "*");
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
