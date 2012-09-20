/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.bbn.rpki.test.util.Util;

/**
 * Common base class for deleting remote files from a particular publication
 * point
 *
 * @author tomlinso
 */
public abstract class DeleteRemoteFiles extends TaskFactory {
  protected abstract class Task extends TaskFactory.Task {

    protected final File publicationSource;

    protected Task(String taskName, File publicationSource) {
      super(taskName);
      this.publicationSource = publicationSource;
    }

    @Override
    public void run() {
      List<File> supercededFiles = getSupercededFiles();
      if (supercededFiles.isEmpty()) {
        return;
      }
      List<String> cmd = new ArrayList<String>();
      String[] sourceParts = model.getSourcePath(publicationSource);
      String remotePath = model.getRemotePath(sourceParts);
      String serverName = sourceParts[0];
      cmd.addAll(Arrays.asList("ssh",
                               serverName,
                               "cd",
                               remotePath,
      "rm"));
      for (File file : supercededFiles) {
        String name = file.getName();
        cmd.add(name);
      }
      Util.exec(getTaskName(), false, null, null, null, cmd);
      model.deletedFiles(supercededFiles);
    }

    protected abstract List<File> getSupercededFiles();

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return null;
    }
  }

  protected DeleteRemoteFiles(Model model) {
    super(model);
  }
}
