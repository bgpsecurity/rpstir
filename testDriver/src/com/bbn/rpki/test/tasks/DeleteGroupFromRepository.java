/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import com.bbn.rpki.test.tasks.ExtensionHandler.ExtensionFilter;

/**
 * Delete a bunch of files from a publication point.
 * 
 * The group is defined by the publication point and the extension of the files
 *
 * @author tomlinso
 */
public class DeleteGroupFromRepository extends DeleteRemoteFiles {
  /**
   * Encapsulates the factory-specific parameters
   * @author tomlinso
   */
  public static class Args {

    private final File publicationSource;
    private final ExtensionHandler.ExtensionFilter filter;

    /**
     * @param publicationSource
     * @param filter
     */
    public Args(File publicationSource, ExtensionFilter filter) {
      this.publicationSource = publicationSource;
      this.filter = filter;
    }

  }

  protected class Task extends DeleteRemoteFiles.Task {

    private final List<File> groupFiles;

    /**
     * @param taskName
     * @param publicationSource
     */
    protected Task(String taskName, File publicationSource, List<File> groupFiles) {
      super(taskName, publicationSource);
      this.groupFiles = groupFiles;
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
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

  private final Args args;

  /**
   * @param model
   * @param args
   */
  public DeleteGroupFromRepository(Model model, Args args) {
    super(model);
    this.args = args;
  }

  @Override
  protected Task reallyCreateTask(String extension) {
    File[] files = args.publicationSource.listFiles(args.filter);
    return new Task(extension, args.publicationSource, Arrays.asList(files));
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  protected void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns here
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    return Arrays.asList(ExtensionHandler.extensions);
  }
}
