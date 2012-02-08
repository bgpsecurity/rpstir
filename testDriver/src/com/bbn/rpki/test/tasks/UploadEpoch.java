/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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
public class UploadEpoch extends TaskFactory {

  /**
   * 
   */
  static final String TASK_NAME = "UploadEpoch";

  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task() {
      super(TASK_NAME);
    }

    @Override
    public void run() {
      for (TaskFactory.Task task : getSubtasks()) {
        task.run();
      }
    }

    private List<TaskFactory.Task> getSubtasks() {
      List<File> roots = model.getRepositoryRoots();
      List<TaskFactory.Task> ret = new ArrayList<TaskFactory.Task>(roots.size());
      UploadRepositoryRoot factory = model.getTaskFactory(UploadRepositoryRoot.class);
      for (File repositoryRootDir : roots) {
        String repositoryRootName = model.getRepositoryRootName(repositoryRootDir);
        ret.add(factory.createTask(repositoryRootName));
      }
      return ret;
    }

    private List<TaskFactory.Task> getSubtasksByNode() {
      List<File> nodeDirectories = model.getNodeDirectories();
      List<TaskFactory.Task> ret = new ArrayList<TaskFactory.Task>(nodeDirectories.size());
      UploadNode factory = model.getTaskFactory(UploadNode.class);
      for (File nodeDir : nodeDirectories) {
        String nodeName = model.getNodeName(nodeDir);
        ret.add(factory.createTask(nodeName));
      }
      return ret;
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      if (getSelectedTaskBreakdown() != null) {
        return getSelectedTaskBreakdown().getTasks().size() + " sub-tasks";
      }
      return getSubtasksByNode().size() + " nodes";
    }
  }

  /**
   * @param model
   */
  public UploadEpoch(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  public void appendBreakdowns(List<Breakdown> list) {
    list.add(new Breakdown("byRepositoryRoot") {
      @Override
      public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
        Task parentTask = (Task) task;
        return new TaskBreakdown(getBreakdownName(), parentTask, parentTask.getSubtasks());
      }
    });
    list.add(new Breakdown("byNode") {
      @Override
      public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
        Task parentTask = (Task) task;
        return new TaskBreakdown(getBreakdownName(), parentTask, parentTask.getSubtasksByNode());
      }
    });
  }

  /**
   * @param taskName
   * @return a new Task
   */
  @Override
  public Task createTask(String taskName) {
    assert TASK_NAME.equals(taskName);
    return new Task();
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    return Collections.singleton(TASK_NAME);
  }
}
