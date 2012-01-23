/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.List;

/**
 * Delete a bunch of files from a publication point. Current usage is for all
 * files in a group to be of the same type (extension).
 *
 * @author tomlinso
 */
public class DeleteGroupFromRepository extends DeleteRemoteFiles {

  private final List<File> groupFiles;
  /**
   * @param model
   * @param extension
   * @param publicationSource
   * @param groupFiles
   */
  public DeleteGroupFromRepository(Model model,
                                   String extension,
                                   File publicationSource,
                                   List<File> groupFiles) {
    super(extension, model, publicationSource);
    this.groupFiles = groupFiles;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return String.format("Delete Group of %d Files", groupFiles.size());
  }

  /**
   * @see com.bbn.rpki.test.tasks.DeleteRemoteFiles#getSupercededFiles()
   */
  @Override
  protected List<File> getSupercededFiles() {
    return groupFiles;
  }

}
