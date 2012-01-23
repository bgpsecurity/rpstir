/*
 * Created on Jan 18, 2012
 */
package com.bbn.rpki.test.tasks;

import com.bbn.rpki.test.RunLoader;

/**
 * Start the loader process.
 * 
 * This is not actually used as a Task and may go away
 *
 * @author tomlinso
 */
public class StartLoader extends Task {

  /**
   * @param model
   */
  public StartLoader(Model model) {
    super("StartLoader", model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    RunLoader.singleton().start();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(String)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(String n) {
    return null;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getLogDetail()
   */
  @Override
  protected String getLogDetail() {
    return "Loader started";
  }

}
