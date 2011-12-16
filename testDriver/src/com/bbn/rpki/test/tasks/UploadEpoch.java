/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Uploads a model
 *
 * @author tomlinso
 */
public class UploadEpoch extends Task {
  
  private final Model model;
  private final List<Task> subtasks;
  private final int epochIndex;
 
  /**
   * @param model
   * @param epochIndex 
   */
  public UploadEpoch(Model model, int epochIndex) {
    this.model = model;
    this.epochIndex = epochIndex;
    subtasks = getSubtasks();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    for (Task task : subtasks) {
      task.run();
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 1;
  }

  /**
   * Break down this task into its individual roots
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert n == 0;
    return new TaskBreakdown(subtasks, TaskBreakdown.Type.PARALLEL);
  }

  private List<Task> getSubtasks() {
    List<File> roots = model.getRepositoryRoots(epochIndex);
    Map<String, File> prevRoots = new TreeMap<String, File>();
    if (epochIndex > 0) {
      for (File root : model.getRepositoryRoots(epochIndex - 1)) {
        prevRoots.put(root.getName(), root);
      }
    }
    List<Task> ret = new ArrayList<Task>(roots.size());
    for (File repositoryRootDir : roots) {
      File previousRootDir = prevRoots.get(repositoryRootDir.getName());
      ret.add(new UploadRepositoryRoot(model, repositoryRootDir, previousRootDir));
    }
    return ret;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return subtasks.size() + " sub-tasks";
  }
}
