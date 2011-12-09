/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Uploads a model
 *
 * @author tomlinso
 */
public class UploadEpoch implements Task {
  private static final FileFilter dirFilter = new FileFilter() {

    @Override
    public boolean accept(File f) {
      return f.isDirectory();
    }};
  private final Model model;
 
  /**
   * @param model
   */
  public UploadEpoch(Model model) {
    this.model = model;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
    File modelDir = model.getEpochDir(epochIndex);
    String repository = model.getRepository();
    List<String> cmd = new ArrayList<String>();
    cmd.add("scp");
    cmd.add("-qr");
    for (File file : modelDir.listFiles()) {
      cmd.add(file.getPath());
    }
    cmd.add(repository);
    String[] cmdArray = cmd.toArray(new String[cmd.size()]);
    Util.exec(cmdArray, "UploadModel", false, Util.RPKI_ROOT);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 1;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert n == 0;
    List<Task> subtasks = new ArrayList<Task>();
    // A task for each sub-directory
    buildTasks(subtasks, model.getEpochDir(epochIndex), model.getRepository());
    return new TaskBreakdown(subtasks, TaskBreakdown.Type.PARALLEL);
  }

  private void buildTasks(List<Task> subtasks, File dir, String repository) {
    File[] subdirs = dir.listFiles(dirFilter);
    subtasks.add(new UploadNode(dir, repository));
    for (File subdir : subdirs) {
      String subrep = repository + "/" + subdir.getName();
      buildTasks(subtasks, subdir, subrep);
    }
  }
  
  
}
