/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import java.io.File;

import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class InitializeRepositories extends Task {

  private final Model model;

  /**
   * @param model
   */
  public InitializeRepositories(Model model) {
    this.model = model;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    for (int epochIndex = 0; epochIndex < model.getEpochCount(); epochIndex++) {
      for (File root : model.getRepositoryRoots(epochIndex)) {
        Util.exec("Initialize Repository", false, null, null,
            null,
            "ssh",
            model.getServerName(root),
            "rm",
            "-rf", model.getUploadRepositoryFileName(root, new File(root, "*")));
      }
    }
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
    // TODO Auto-generated method stub
    return null;
  }

}
