/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;

import com.bbn.rpki.test.objects.Util;

/**
 * A task for re-initializing the cache
 *
 * @author tomlinso
 */
public class InitializeCache extends Task {
  
  private static final String RSYNC_AUR_LOG = "rsync_aur.log";
  private static final String RCLI_LOG = "rcli.log";
  private static final String REPOSITORY = "REPOSITORY";
  private static final String LOGS = "LOGS";
  private final Model model;
  
  /**
   * @param model
   */
  public InitializeCache(Model model) {
    this.model = model;
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    Util.deleteDirectories(new File(model.getRPKIRoot(), REPOSITORY), new File(model.getRPKIRoot(), LOGS));
    Util.killProcessesRunning("run_scripts/loader.sh");
    File rpkiRoot = model.getRPKIRoot();
    new File(rpkiRoot, RCLI_LOG).delete();
    new File(rpkiRoot, RSYNC_AUR_LOG).delete();
    Util.initDB();
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
