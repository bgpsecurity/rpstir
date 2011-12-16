/*
 * Created on Dec 13, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.Component;
import java.awt.Container;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JSplitPane;

import com.bbn.rpki.test.RunLoader;
import com.bbn.rpki.test.Test;
import com.bbn.rpki.test.TestBasic;
import com.bbn.rpki.test.TestExpanded;
import com.bbn.rpki.test.TestUpdateEveryStep;
import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class Main {
  private final TypescriptPanel tsPanel = new TypescriptPanel("Process Output");
  private final TypescriptPanel loaderPanel = new TypescriptPanel("Loader Typescript");
  private final TypescriptPanel tlPanel = new TypescriptPanel("Task Log");
  private final Component leftPanel = loaderPanel.getComponent();
  private final Component rightPanel = tsPanel.getComponent();
  private final JSplitPane leftRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
  private final JSplitPane topBottom = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tlPanel.getComponent(), leftRight);
  private String[] args;
  
  /**
   * @param args
   * @throws IOException 
   */
  public Main(String[] args) {
    Util.setTypescriptLogger(tsPanel);
    RunLoader.singleton().setTypescriptLogger(loaderPanel);
    leftRight.setDividerLocation(0.5);
    leftRight.setResizeWeight(0.5);
    topBottom.setDividerLocation(0.5);
    topBottom.setResizeWeight(0.5);
    this.args = args;
  }
  
  void run() throws IOException {
    if (args.length == 0) {
      args = new String[] {"TestModel"};
    }
    for (String arg : args) {
      Model model = new Model(Util.RPKI_ROOT, new File(Util.RPKI_ROOT, arg));
      Test[] tests = {
          new TestBasic(model),
          new TestExpanded(model),
          new TestUpdateEveryStep(model),
      };
      RunLoader.singleton().start();
      for (Test test : tests) {
        String testName = test.getClass().getSimpleName();
        System.out.println("Starting " + testName);
        List<Task> tasks = test.getTasks();
        for (Task task : tasks) {
          tlPanel.log(task.toString() + "...");
          task.run();
          tlPanel.log("done\n");
        }
        System.out.println(testName + " completed");
      }
      RunLoader.singleton().stop();
    }
  }

  Container getComponent() {
    return topBottom;
  }
  
  /**
   * @param args
   * @throws IOException 
   */
  public static void main(String[] args) throws IOException {
    Main main = new Main(args);
    JFrame frame = new JFrame("Test Driver");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setContentPane(main.getComponent());
    frame.pack();
    frame.setVisible(true);
    main.run();
  }

}
