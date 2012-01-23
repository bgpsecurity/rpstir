/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.List;

/**
 * A Task to upload a number of files to a single publication point.
 *
 * @author tomlinso
 */
public class UploadGroup extends UploadFiles {

  private final List<File> files;

  /**
   * @param taskName
   * @param model
   * @param publicationSource
   * @param files
   */
  public UploadGroup(String taskName, Model model, File publicationSource, List<File> files) {
    super(taskName, model, publicationSource);
    this.files = files;
  }

  /**
   * @see com.bbn.rpki.test.tasks.UploadFiles#getFilesToUpload()
   */
  @Override
  protected List<File> getFilesToUpload() {
    return files;
  }
}
