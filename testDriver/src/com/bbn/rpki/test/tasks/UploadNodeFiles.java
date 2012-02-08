/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Task to upload one node
 * 
 * Can be broken down into individual UploadFile tasks for each file in the node
 *
 * @author tomlinso
 */
public class UploadNodeFiles extends UploadFiles {

  private final ExtensionHandler xHandler = new ExtensionHandler();

  /**
   * @param model
   * @param nodeDir
   */
  public UploadNodeFiles(Model model, File nodeDir) {
    super(model, new Args(nodeDir, null));
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  public void appendBreakdowns(List<Breakdown> list) {
    for (String bdn : xHandler.getBreakdownNames()) {
      final String breakdownName = bdn;
      list.add(new Breakdown(breakdownName) {
        @Override
        public TaskBreakdown getTaskBreakdown(TaskFactory.Task task) {
          ExtensionHandler.ExtensionFilter[] filters =
            xHandler.getExtensionFilter(breakdownName);
          Task parentTask = (Task) task;
          List<TaskFactory.Task> tasks = new ArrayList<TaskFactory.Task>();
          for (ExtensionHandler.ExtensionFilter filter : filters) {
            UploadFiles.Args args = new UploadFiles.Args(directory, filter);
            UploadFiles subFactory = model.getTaskFactory(UploadFiles.class, args);
            tasks.add(subFactory.createTask(filter.getExtension()));
          }
          return new TaskBreakdown(breakdownName, parentTask, tasks);
        }
      });
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#getTaskNames()
   */
  @Override
  public Collection<String> getTaskNames() {
    return null;
  }
}