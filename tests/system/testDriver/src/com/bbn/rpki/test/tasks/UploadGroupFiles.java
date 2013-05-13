/*
 * Created on Feb 10, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class UploadGroupFiles extends UploadFiles {

  private final File nodeDir;

  /**
   * @param model
   * @param nodeDir
   */
  public UploadGroupFiles(Model model, File nodeDir) {
    super(model);
    this.nodeDir = nodeDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#reallyCreateTask(java.lang.String)
   */
  @Override
  protected Task reallyCreateTask(String relativeTaskName) {
    ExtensionHandler.ExtensionFilter filter = new ExtensionHandler.ExtensionFilter(relativeTaskName);
    return new Task(relativeTaskName, nodeDir, filter);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getRelativeTaskNames()
   */
  @Override
  protected Collection<String> getRelativeTaskNames() {
    return Arrays.asList(ExtensionHandler.extensions);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // No further breakdowns to append
  }

}
