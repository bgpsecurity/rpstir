/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Task to upload one node
 * 
 * Can be broken down into individual UploadFile tasks for each file in the node
 *
 * @author tomlinso
 */
public class UploadNodeFiles extends UploadFiles {

  private final ExtensionHandler xHandler;

  /**
   * @param model
   * @param nodeDir
   */
  public UploadNodeFiles(Model model, File nodeDir) {
    super("upload(" + model.getNodeName(nodeDir) + ")", model, nodeDir);
    xHandler = new ExtensionHandler();
  }

  @Override
  protected List<File> getFilesToUpload() {
    List<File> filesToUpload = new ArrayList<File>();
    for (File file : model.getWrittenFiles()) {
      if (file.getParentFile().equals(nodeDir)) {
        filesToUpload.add(file);
      }
    }
    return filesToUpload;
  }

  /**
   * The one breakdown case we have is to upload individual files as separate,
   * parallel tasks
   * 
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String breakdownName) {
    List<ExtensionHandler.Group> groups =
      xHandler.getGroups(breakdownName, getFilesToUpload());
    List<Task> tasks = new ArrayList<Task>();
    for (ExtensionHandler.Group group : groups) {
      List<File> files = group.getFiles();
      tasks.add(new UploadGroup(group.getExtension(), model, nodeDir, files));
    }
    return new TaskBreakdown(breakdownName, this, tasks);
  }
}
