/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class DeleteRepositoryFile extends Task {

  private final String serverName;
  private final String fileName;

  /**
   * @param serverName
   * @param fileName
   */
  public DeleteRepositoryFile(String serverName, String fileName) {
    this.serverName = serverName;
    this.fileName = fileName;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    String[] cmdArray = {
        "ssh",
        serverName,
        "rm",
        "-rf",
        fileName
    };
    Util.exec(cmdArray, "DeleteRepositoryFile", false, null, null);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert false;
    return null;
  }
}
