/*
 * Created on Feb 10, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Creates tasks to upload trust anchors to a repository root
 *
 * @author tomlinso
 */
public class UploadTrustAnchors extends UploadFiles {

  /**
   * @param model
   */
  public UploadTrustAnchors(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#reallyCreateTask(java.lang.String)
   */
  @Override
  protected com.bbn.rpki.test.tasks.TaskFactory.Task reallyCreateTask(String relativeTaskName) {
    File rootDir = model.getRepositoryRoot(relativeTaskName);
    return new Task(relativeTaskName, rootDir, new ExtensionHandler.ExtensionFilter("cer"));
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getRelativeTaskNames()
   */
  @Override
  protected Collection<String> getRelativeTaskNames() {
    List<String> ret = new ArrayList<String>();
    for (File rootDir : model.getRepositoryRoots()) {
      ret.add(model.getRepositoryRootName(rootDir));
    }
    return ret;
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns to append
  }

}
