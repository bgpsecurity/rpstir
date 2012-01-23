/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * UPloads multiple files to a publication point
 *
 * @author tomlinso
 */
public abstract class UploadFiles extends Task {

  protected final File nodeDir;

  protected UploadFiles(String taskName, Model model, File nodeDir) {
    super(taskName, model);
    this.nodeDir = nodeDir;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<File> filesToUpload = getFilesToUpload();
    if (filesToUpload.isEmpty()) {
      return;
    }
    List<String> cmd = new ArrayList<String>();
    String repository = model.getSCPFileNameArg(nodeDir);
    cmd.add("scp");
    cmd.add("-qB");
    for (File file : filesToUpload) {
      cmd.add(file.getPath());
    }
    cmd.add(repository);
    Util.exec("UploadNode", false, Util.RPKI_ROOT, null, null, cmd);
  }

  protected abstract List<File> getFilesToUpload();
  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected final String getLogDetail() {
    String repository = model.getSCPFileNameArg(nodeDir);
    return String.format("%d files to %s", getFilesToUpload().size(), repository);
  }
}
