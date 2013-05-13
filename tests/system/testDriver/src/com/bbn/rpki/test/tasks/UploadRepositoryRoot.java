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
public class UploadRepositoryRoot extends TaskFactory {

  protected class Task extends TaskFactory.Task {

    private final File repositoryRootDir;

    /**
     * @param taskName
     */
    protected Task(File repositoryRootDir) {
      super(repositoryRootDir.getName());
      this.repositoryRootDir = repositoryRootDir;
    }

    public File getRepositoryRootDir() {
      return repositoryRootDir;
    }

    @Override
    public void run() {
      // We use the one and only breakdown
      Breakdown breakdown = getBreakdowns().iterator().next();
      for (com.bbn.rpki.test.tasks.TaskFactory.Task task : breakdown.getTaskBreakdown(this).getTasks()) {
        task.run();
      }
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return repositoryRootDir.getName();
    }
  }

  /**
   * @param model
   */
  public UploadRepositoryRoot(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskBreakdown(java.lang.String)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    list.add(new Breakdown("byNode") {
      @Override
      public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
        UploadRepositoryRoot.Task parentTask = (Task) task;
        List<TaskFactory.Task> tasks = new ArrayList<TaskFactory.Task>();
        UploadNode factory = model.getTaskFactory(UploadNode.class);
        for (File nodeDir :model.getNodeDirectories()) {
          File rootDir = model.getRootDirectory(nodeDir);
          if (rootDir.equals(parentTask.repositoryRootDir)) {
            String nodeName = model.getNodeName(nodeDir);
            tasks.add(factory.createRelativeTask(nodeName));
          }
        }
        // TODO Trust anchors are certs in the repository root(for now)
        UploadTrustAnchors uploadTrustAnchorsFactory = model.getTaskFactory(UploadTrustAnchors.class);
        String rootName = model.getRepositoryRootName(parentTask.getRepositoryRootDir());
        uploadTrustAnchorsFactory.createRelativeTask(rootName);
        return new TaskBreakdown(getBreakdownName(), parentTask, tasks);
      }
    });
  }

  @Override
  protected Task reallyCreateTask(String repositoryRootName) {
    File repositoryRootDir = model.getRepositoryRoot(repositoryRootName);
    return new Task(repositoryRootDir);
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    Collection<File> roots = model.getRepositoryRoots();
    List<String> ret = new ArrayList<String>();
    for (File root : roots) {
      String repositoryRootName = model.getRepositoryRootName(root);
      ret.add(repositoryRootName);
    }
    return ret;
  }
}
