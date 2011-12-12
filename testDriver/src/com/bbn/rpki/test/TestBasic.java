/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import com.bbn.rpki.test.tasks.Model;

/**
 * Performs the simplest possible execution of the model by initializing and
 * then uploading everything and updating the cache for every epoch
 *
 * @author tomlinso
 */
public class TestBasic extends Test {
  
  /**
   * @param model
   */
  public TestBasic(Model model) {
    super(model);
  }
}
