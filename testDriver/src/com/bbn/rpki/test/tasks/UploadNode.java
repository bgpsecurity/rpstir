/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Task to upload a repository root.
 * 
 * There are two breakdowns:
 *   deleteFirst has two subtasks to delete and upload in that order
 *   uploadFirst has two subtasks to upload and delete in that order
 *
 * @author tomlinso
 */
public class UploadNode extends TaskFactory {
  protected class Task extends TaskFactory.Task {
    private final File nodeDir;
    private TaskFactory.Task uploadTask;
    private TaskFactory.Task deleteTask;
    private TaskFactory.Task mkdirTask;

    Task(File nodeDir) {
      super(getModel().getNodeName(nodeDir));
      this.nodeDir = nodeDir;
    }

    private TaskFactory.Task getUploadTask() {
      if (uploadTask == null) {
        UploadNodeFiles factory = model.getTaskFactory(UploadNodeFiles.class);
        uploadTask = factory.createRelativeTask(model.getNodeName(nodeDir));
      }
      return uploadTask;
    }

    private TaskFactory.Task getDeleteTask() {
      if (deleteTask == null) {
        String nodeName = model.getNodeName(nodeDir);
        DeleteFromRepositoryNode factory = model.getTaskFactory(DeleteFromRepositoryNode.class);
        deleteTask = factory.createRelativeTask(nodeName);
      }
      return deleteTask;
    }

    private TaskFactory.Task getMkdirTask() {
      if (mkdirTask == null) {
        MakeNodeDir factory = model.getTaskFactory(MakeNodeDir.class);
        mkdirTask = factory.createRelativeTask(model.getNodeName(nodeDir));
      }
      return mkdirTask;
    }

    @Override
    public void run() {
      getMkdirTask().run();
      getUploadTask().run();
      getDeleteTask().run();
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      if (getSelectedTaskBreakdown() == null) {
        return String.format("%s upload %s and delete %s", nodeDir.getName(), getUploadTask().getLogDetail(), getDeleteTask().getLogDetail());
      }
      return nodeDir.getName();
    }
  }

  /**
   * @param model
   */
  public UploadNode(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskBreakdown(java.lang.String)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    list.add(new Breakdown("deleteFirst") {
      @Override
      public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
        Task parentTask = (Task) task;
        return new TaskBreakdown(getBreakdownName(), parentTask,
                                 parentTask.getMkdirTask(),
                                 parentTask.getDeleteTask(),
                                 parentTask.getUploadTask());
      }
    });
    list.add(new Breakdown("updateFirst") {
      @Override
      public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
        Task parentTask = (Task) task;
        return new TaskBreakdown(getBreakdownName(), parentTask,
                                 parentTask.getMkdirTask(),
                                 parentTask.getUploadTask(),
                                 parentTask.getDeleteTask());
      }
    });
  }

  @Override
  protected Task reallyCreateTask(String taskName) {
    assert getRelativeTaskNames().contains(taskName);
    File nodeDir = model.getNodeDirectory(taskName);
    return new Task(nodeDir);
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    List<File> nodeDirs = model.getNodeDirectories();
    List<String> ret = new ArrayList<String>(nodeDirs.size());
    for (File nodeDir : nodeDirs) {
      ret.add(model.getNodeName(nodeDir));
    }
    return ret;
  }
}
