/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;


/**
 * Runs the tests on models specified on the command line
 *
 * @author tomlinso
 */
public class TestDriver {

  /**
   * @param args
   * @throws IOException 
   */
  public static void main(String[] args) throws IOException {
    if (args.length == 0) {
      args = new String[] {"TestModel"};
    }
    for (String arg : args) {
      Model model = new Model(Util.RPKI_ROOT, new File(Util.RPKI_ROOT, arg));
      Test[] tests = {
          new TestBasic(model),
//          new TestExpanded(model),
//          new TestUpdateEveryStep(model),
      };
      RunLoader.singleton().start();
      for (Test test : tests) {
        String testName = test.getClass().getSimpleName();
        System.out.println("Starting " + testName);
        List<Task> tasks = test.getTasks();
        for (Task task : tasks) {
          task.run();
        }
        System.out.println(testName + " completed");
      }
      RunLoader.singleton().stop();
    }
  }
}
