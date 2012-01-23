/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class DeleteFromRepositoryNode extends DeleteRemoteFiles {
  private final ExtensionHandler xHandler;

  /**
   * @param model
   * @param nodeDir
   */
  public DeleteFromRepositoryNode(Model model, File nodeDir) {
    super("delete(" + nodeDir.getName() + ")", model, nodeDir);
    xHandler = new ExtensionHandler();
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
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String breakdownName) {
    List<ExtensionHandler.Group> groups =
      xHandler.getGroups(breakdownName, getSupercededFiles());
    List<Task> tasks = new ArrayList<Task>();
    for (ExtensionHandler.Group group : groups) {
      tasks.add(new DeleteGroupFromRepository(model, group.getExtension() ,publicationSource, group.getFiles()));
    }
    return new TaskBreakdown(breakdownName, this, tasks);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return getSupercededFiles().size() + " files";
  }
}
