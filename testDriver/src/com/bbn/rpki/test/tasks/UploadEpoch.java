/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Uploads a model.
 * 
 * There are two breakdowns:
 *   byRepositoryRoot -- provides tasks for uploading individual roots
 *   byNode -- provides tasks for uploading individual nodes
 *
 * @author tomlinso
 */
public class UploadEpoch extends Task {

  /**
   * @param model
   */
  public UploadEpoch(Model model) {
    super("UploadEpoch", model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    for (Task task : getSubtasks()) {
      task.run();
    }
  }

  /**
   * Break down this task into its individual roots
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String breakdownName) {
    if ("byRepositoryRoot".equals(breakdownName)) {
      return new TaskBreakdown(breakdownName, this, getSubtasks());
    }
    if ("byNode".equals(breakdownName)) {
      return new TaskBreakdown(breakdownName, this, getSubtasksByNode());
    }
    return null;
  }

  private List<Task> getSubtasks() {
    List<File> roots = model.getRepositoryRoots();
    List<Task> ret = new ArrayList<Task>(roots.size());
    for (File repositoryRootDir : roots) {
      ret.add(new UploadRepositoryRoot(model, repositoryRootDir));
    }
    return ret;
  }

  private List<Task> getSubtasksByNode() {
    List<File> nodeDirectories = model.getNodeDirectories();
    List<Task> ret = new ArrayList<Task>(nodeDirectories.size());
    for (File nodeDir : nodeDirectories) {
      ret.add(new UploadNode(model, nodeDir));
    }
    return ret;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    if (getSelectedBreakdown() != null) {
      return getSelectedBreakdown().getTasks().size() + " sub-tasks";
    }
    return getSubtasksByNode().size() + " nodes";
  }
}
