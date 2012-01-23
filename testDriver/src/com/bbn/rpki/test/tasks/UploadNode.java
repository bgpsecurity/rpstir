/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;

/**
 * Task to upload a repository root.
 * 
 * There are two breakdowns:
 *   deleteFirst has two subtasks to delete and upload in that order
 *   uploadFirst has two subtasks to upload and delete in that order
 *
 * @author tomlinso
 */
public class UploadNode extends Task {

  private final File nodeDir;
  private UploadNodeFiles uploadTask;
  private DeleteFromRepositoryNode deleteTask;

  UploadNode(Model model, File nodeDir) {
    super(model.getNodeName(nodeDir), model);
    this.nodeDir = nodeDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(java.lang.String)
   */
  @Override
  protected TaskBreakdown getTaskBreakdown(String breakdownName) {
    if ("deleteFirst".equals(breakdownName)) {
      return new TaskBreakdown(breakdownName, this, getDeleteTask(), getUploadTask());
    }
    if ("updateFirst".equals(breakdownName)) {
      return new TaskBreakdown(breakdownName, this, getUploadTask(), getDeleteTask());
    }
    return null;
  }

  private Task getUploadTask() {
    if (uploadTask == null) {
      uploadTask = new UploadNodeFiles(model, nodeDir);
    }
    return uploadTask;
  }

  private Task getDeleteTask() {
    if (deleteTask == null) {
      deleteTask = new DeleteFromRepositoryNode(model, nodeDir);
    }
    return deleteTask;
  }



  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    new UploadNodeFiles(model, nodeDir).run();
    new DeleteFromRepositoryNode(model, nodeDir).run();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    if (getSelectedBreakdown() == null) {
      return String.format("%s upload %s and delete %s", nodeDir.getName(), getUploadTask().getLogDetail(), getDeleteTask().getLogDetail());
    }
    return nodeDir.getName();
  }
}
