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
public class ReinitializeCache implements Task {
  
  private static final String RSYNC_AUR_LOG = "rsync_aur.log";
  private static final String RCLI_LOG = "rcli.log";
  private static final String REPOSITORY = "REPOSITORY";
  private static final String LOGS = "LOGS";
  private final Model model;
  
  /**
   * @param model
   */
  public ReinitializeCache(Model model) {
    this.model = model;
  }
  
  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
    if (epochIndex > 0) return;
    Util.deleteDirectories(new File(model.getRoot(), REPOSITORY), new File(LOGS));
    Util.killProcessesRunning("run_scripts/loader.sh");
    File rpkiRoot = model.getRoot();
    new File(rpkiRoot, RCLI_LOG).delete();
    new File(rpkiRoot, RSYNC_AUR_LOG);
    Util.initDB();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert false;
    return null;
  }

}
