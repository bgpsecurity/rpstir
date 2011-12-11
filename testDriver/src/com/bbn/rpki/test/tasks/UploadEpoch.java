/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Uploads a model
 *
 * @author tomlinso
 */
public class UploadEpoch implements Task {
  
  private final Model model;
 
  /**
   * @param model
   */
  public UploadEpoch(Model model) {
    this.model = model;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
    List<Task> subtasks = getSubtasks(epochIndex);
    for (Task task : subtasks) {
      task.run(epochIndex);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 1;
  }

  /**
   * Break down this task into its individual roots
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert n == 0;
    List<Task> subtasks = getSubtasks(epochIndex);
    return new TaskBreakdown(subtasks, TaskBreakdown.Type.PARALLEL);
  }

  private List<Task> getSubtasks(int epochIndex) {
    List<File> roots = model.getRepositoryRoots(epochIndex);
    List<Task> ret = new ArrayList<Task>(roots.size());
    for (File repositoryRootDir : roots) {
      ret.add(new UploadRepositoryRoot(model, repositoryRootDir));
    }
    return ret;
  }  
}
