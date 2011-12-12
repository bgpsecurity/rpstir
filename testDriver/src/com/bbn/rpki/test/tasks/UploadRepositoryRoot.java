/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;

/**
 * Task to upload a repository root.
 *
 * @author tomlinso
 */
public class UploadRepositoryRoot extends CompoundTask {
  UploadRepositoryRoot(Model model, File repositoryRootDir, File previousRootDir) {
    super(TaskBreakdown.Type.SHUFFLE);
    if (previousRootDir != null) {
      tasks.add(new DeleteFromRepositoryRoot(model, repositoryRootDir, previousRootDir));
    }
    tasks.add(new UploadRepositoryRootFiles(model, repositoryRootDir));
  }
}
