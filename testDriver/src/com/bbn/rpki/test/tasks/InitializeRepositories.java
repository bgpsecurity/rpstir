/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class InitializeRepositories extends Task {

  /**
   * @param model
   */
  public InitializeRepositories(Model model) {
    super("InitializeRepositories", model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
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
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    // There no breakdowns
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    // TODO Auto-generated method stub
    return null;
  }

}
