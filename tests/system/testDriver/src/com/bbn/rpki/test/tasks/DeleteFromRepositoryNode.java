/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Delete files from a specific repository node.
 * 
 * The specific files to be deleted are obtained from the model as determined
 * by the changes that have occured in the model
 *
 * @author tomlinso
 */
public class DeleteFromRepositoryNode extends DeleteRemoteFiles {
  protected class Task extends DeleteRemoteFiles.Task {

    /**
     * @param taskName
     * @param publicationSource
     */
    protected Task(String taskName, File publicationSource) {
      super(taskName, publicationSource);
    }

    /**
     * @return
     */
    @Override
    protected List<File> getSupercededFiles() {
      List<File> supercededFiles = new ArrayList<File>();
      for (File file : model.getSupercededFiles()) {
        if (file.getParentFile().equals(publicationSource)) {
          supercededFiles.add(file);
        }
      }
      return supercededFiles;
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return getSupercededFiles().size() + " files";
    }
  }

  private final ExtensionHandler xHandler = new ExtensionHandler();

  /**
   * @param model
   */
  public DeleteFromRepositoryNode(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskBreakdown(String)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    for (String bdn : xHandler.getBreakdownNames()) {
      final String breakdownName = bdn;
      list.add(new Breakdown(breakdownName) {
        @Override
        public TaskBreakdown getTaskBreakdown(TaskFactory.Task parentTask) {
          ExtensionHandler.ExtensionFilter[] filters = xHandler.getExtensionFilter(breakdownName);
          List<TaskFactory.Task> tasks = new ArrayList<TaskFactory.Task>();
          for (ExtensionHandler.ExtensionFilter filter : filters) {
            DeleteGroupFromRepository.Args args = new DeleteGroupFromRepository.Args(((Task) parentTask).publicationSource, filter);
            DeleteGroupFromRepository subFactory = model.getTaskFactory(DeleteGroupFromRepository.class, args);
            tasks.add(subFactory.createRelativeTask(filter.getExtension()));
          }
          return new TaskBreakdown(breakdownName, parentTask, tasks);
        }

      });
    }
  }

  @Override
  protected Task reallyCreateTask(String relativeTaskName) {
    File nodeDir = model.getNodeDirectory(relativeTaskName);
    return new Task(relativeTaskName, nodeDir);
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    List<String> ret = new ArrayList<String>();
    for (File nodeDir : model.getNodeDirectories()) {
      ret.add(model.getNodeName(nodeDir));
    }
    return ret;
  }
}
