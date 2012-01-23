/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Task to upload one file
 *
 * @author tomlinso
 */
public class UploadFile extends Task {

  private final File file;
  /**
   * @param model
   * @param file
   */
  public UploadFile(Model model, File file) {
    super("Upload " + file.getName(), model);
    this.file = file;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    List<String> cmd = new ArrayList<String>();
    cmd.add("scp");
    cmd.add(file.getPath());
    cmd.add(model.getSCPFileNameArg(file));
    Util.exec("UploadFile", false, Util.RPKI_ROOT, null, null, cmd);
    model.uploadedFile(file);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    assert false;
    return null;
  }

  /**
   * @return the file
   */
  public File getFile() {
    return file;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    String repository = model.getSCPFileNameArg(file);
    return String.format("%s to %s", file, repository);
  }
}
