/*
 * Created on Dec 13, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import com.bbn.rpki.test.RunLoader;
import com.bbn.rpki.test.actions.ui.ActionsEditor;
import com.bbn.rpki.test.tasks.CheckCacheStatus;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.UpdateCache;
import com.bbn.rpki.test.util.Util;

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
  private final String[] args;
  protected boolean run;

  /**
   * @param args
   */
  public Main(String[] args) {
    Util.setTypescriptLogger(tsPanel);
    RunLoader.singleton().setTypescriptLogger(loaderPanel);
    leftRight.setDividerLocation(0.5);
    leftRight.setResizeWeight(0.5);
    topBottom.setDividerLocation(0.5);
    topBottom.setResizeWeight(0.5);
    if (args.length == 0) {
      this.args = new String[] {"smaller.ini"};
    } else {
      this.args = args;
    }
  }

  void run() throws IOException {
    for (String arg : args) {
      File iniFile = new File(arg);
      assert iniFile.isFile();
      System.out.println("Starting " + iniFile);
      Model model = new Model(Util.RPKI_ROOT, iniFile, tlPanel);
      ActionsEditor actionsEditor = new ActionsEditor(model);
      final JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(leftPanel));
      JPanel buttonsPanel = new JPanel();
      JButton exitButton = new JButton("Exit");
      exitButton.addActionListener(new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          // TODO Auto-generated method stub
          run = false;
          dialog.setVisible(false);
        }
      });
      buttonsPanel.add(exitButton);
      JButton runButton = new JButton("Run");
      runButton.addActionListener(new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          // TODO Auto-generated method stub
          run = true;
          dialog.setVisible(false);
        }
      });
      buttonsPanel.add(runButton);
      dialog.add(buttonsPanel, BorderLayout.SOUTH);
      dialog.setModal(true);
      dialog.setResizable(true);
      dialog.add(actionsEditor.getComponent());
      dialog.pack();
      dialog.setVisible(true);
      if (!run) {
        System.exit(0);
        return;
      }
      Iterable<TaskFactory.Task> tasks = model.getTasks();
      executeTasks(tasks, model, "");
      System.out.println(iniFile + " completed");
      RunLoader.singleton().stop();
    }
  }

  private void executeTasks(Iterable<TaskFactory.Task> tasks, Model model, String indent) {
    for (TaskFactory.Task task : tasks) {
      tlPanel.format("%s%s...", indent, task.toString());
      TaskBreakdown breakdown = task.getSelectedTaskBreakdown();
      Iterable<TaskFactory.Task> subtasks = null;
      if (breakdown == null) {
        task.run();
        if (task.isTestEnabled()) {
          TaskFactory.Task[] subArray = {
              model.getTaskFactory(UpdateCache.class).createOnlyTask(),
              model.getTaskFactory(CheckCacheStatus.class).createOnlyTask(),
          };
          subtasks = Arrays.asList(subArray);
        }
      } else {
        subtasks = breakdown.getTasks();
      }
      if (subtasks != null) {
        tlPanel.format("%n");
        executeTasks(subtasks, model, indent + "  ");
        tlPanel.format("%s...", indent);
      }
      tlPanel.format("done%n");
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
