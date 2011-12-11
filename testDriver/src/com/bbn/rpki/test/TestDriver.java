/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test;

import java.io.File;
import java.io.IOException;

import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TopTask;


/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TestDriver {

  /**
   * @param args
   * @throws IOException 
   */
  public static void main(String[] args) throws IOException {
    Model model = new Model(Util.RPKI_ROOT, new File(Util.RPKI_ROOT, "TestModel"));
    Task mainTask = new TopTask(model);
    for (int epochIndex = 0; epochIndex < model.getEpochCount(); epochIndex++) {
      mainTask.run(epochIndex);
    }
  }

}
