/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.tasks.CheckCacheStatus;
import com.bbn.rpki.test.tasks.InitializeCache;
import com.bbn.rpki.test.tasks.InitializeRepositories;
import com.bbn.rpki.test.tasks.InstallTrustAnchor;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.UpdateCache;
import com.bbn.rpki.test.tasks.UploadEpoch;
import com.bbn.rpki.test.tasks.UploadFile;
import com.bbn.rpki.test.tasks.UploadRepositoryRoot;
import com.bbn.rpki.test.tasks.UploadRepositoryRootFiles;

/**
 * The base of all tests. Maintains the task list.
 *
 * @author tomlinso
 */
public class Test {
  FileFilter certFilter = new FileFilter() {
    @Override
    public boolean accept(File file) {
      return file.isFile() && file.getName().endsWith(".cer");
    }
  };
  protected List<Task> tasks = new ArrayList<Task>();
  protected Model model;
  
  protected Test(Model model) {
    this.model = model;
    tasks.add(new InitializeCache(model));
    tasks.add(new InitializeRepositories(model));
    for (int epochIndex = 0; epochIndex < model.getEpochCount(); epochIndex++) {
      breakDown(new UploadEpoch(model, epochIndex), epochIndex);
    }
    tasks.add(new UpdateCache(model));
    tasks.add(new CheckCacheStatus(model));
  }
  
  private void breakDown(Task task, int epochIndex) {
    int breakdownCount = task.getBreakdownCount();
    TaskBreakdown taskBreakdown;
    if (breakdownCount > 0) {
      taskBreakdown = getTaskBreakdown(task);
    } else {
      taskBreakdown = null;
    }
    if (taskBreakdown == null) {
      addTask(task, epochIndex);
    } else {
      for (Task subtask : taskBreakdown.getTasks()) {
        breakDown(subtask, epochIndex);
      }
    }
  }

  /**
   * Override this to break down tasks differently
   * @param task
   * @return the TaskBreakdown (null by default)
   */
  protected TaskBreakdown getTaskBreakdown(Task task) {
    return null;
  }

  /**
   * @param task
   */
  private void addTask(Task task, int epochIndex) {
    tasks.add(task);
    if (shouldInstallTrustAnchor(task, epochIndex)) {
      tasks.add(new InstallTrustAnchor(model));
    }
    if (shouldUpdateCache(task)) {
      tasks.add(new UpdateCache(model));
      tasks.add(new CheckCacheStatus(model));
    }
  }
  
  /**
   * @param task
   * @return
   */
  private boolean shouldInstallTrustAnchor(Task task, int epochIndex) {
    if (epochIndex == 0) {
      if (task instanceof UploadEpoch) return true;
      if (task instanceof UploadRepositoryRoot) {
        UploadRepositoryRootFiles urr = (UploadRepositoryRootFiles) task;
        File[] topFiles = urr.getRepositoryRootDir().listFiles(certFilter);
        return topFiles.length > 0;
      }
      if (task instanceof UploadFile) {
        UploadFile uploadFileTask = (UploadFile) task;
        File file = uploadFileTask.getFile();
        File rootDir = uploadFileTask.getRepositoryRootDir();
        return file.getParentFile().equals(rootDir) && file.getName().endsWith(".cer");
      }
    }
    // TODO Auto-generated method stub
    return false;
  }

  /**
   * @param task
   * @return
   */
  protected boolean shouldUpdateCache(Task task) {
    // Update the cache after each epoch, by default
    return task instanceof UploadEpoch;
  }

  /**
   * @return the tasks to execute
   */
  public final List<Task> getTasks() {
    return tasks;
  }
}
