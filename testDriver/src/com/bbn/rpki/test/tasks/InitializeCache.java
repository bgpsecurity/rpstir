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
  private static final String REPOSITORY = "REPOSITORY";
  private static final String LOGS = "LOGS";
  /**
   * @param model
   */
  public InitializeCache(Model model) {
    super("InitializeCache", model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    Util.deleteDirectories(new File(model.getRPKIRoot(), REPOSITORY), new File(model.getRPKIRoot(), LOGS));
    new File(Util.RPKI_ROOT, "chaser.log").delete();

    Util.initDB();
    model.clearDatabase();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    // There are no breakdowns
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return null;
  }
}
