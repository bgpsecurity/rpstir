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
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;

import com.bbn.rpki.test.RunLoader;
import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.AllocateAction;
import com.bbn.rpki.test.actions.ChooseCacheCheckTask;
import com.bbn.rpki.test.actions.XMLConstants;
import com.bbn.rpki.test.actions.ui.ActionsEditor;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.Util;
import com.bbn.rpki.test.tasks.CheckCacheStatus;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.UpdateCache;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class Main implements XMLConstants {
  private final TypescriptPanel tsPanel = new TypescriptPanel("Process Output");
  private final TypescriptPanel loaderPanel = new TypescriptPanel("Loader Typescript");
  private final TypescriptPanel tlPanel = new TypescriptPanel("Task Log");
  private final Component leftPanel = loaderPanel.getComponent();
  private final Component rightPanel = tsPanel.getComponent();
  private final JSplitPane leftRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
  private final JSplitPane topBottom = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tlPanel.getComponent(), leftRight);
  private final String[] args;
  protected boolean run;
  protected JFileChooser fileChooser;

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
      this.args = new String[] {"smaller.ini", "../../testDriver/test.xml"};
    } else {
      this.args = args;
    }
  }

  void run() throws IOException, JDOMException {
    File xmlFile;
    if (args.length > 0) {
      xmlFile = new File(args[0]).getAbsoluteFile();
      fileChooser = new JFileChooser(xmlFile.getParentFile());
    } else {
      fileChooser = new JFileChooser();
      if (fileChooser.showOpenDialog(topBottom) != JOptionPane.OK_OPTION) {
        return;
      }
      xmlFile = fileChooser.getSelectedFile();
    }
    SAXBuilder saxBuilder = new SAXBuilder(false);
    Document doc = saxBuilder.build(xmlFile);
    Element rootElement = doc.getRootElement();
    Element iniFileElement = rootElement.getChild(TAG_INI_FILE);
    String iniFileContent = iniFileElement.getText();
    final Model model = new Model(Util.RPKI_ROOT, iniFileContent, tlPanel);
    AbstractAction.createActions(rootElement, model);
    //    buildSomeActions(model);
    ActionsEditor actionsEditor = new ActionsEditor(model);
    final JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(leftPanel));
    JPanel buttonsPanel = new JPanel();
    JButton exitButton = new JButton("Exit");
    exitButton.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        run = false;
        dialog.setVisible(false);
      }
    });
    buttonsPanel.add(exitButton);
    JButton runButton = new JButton("Run");
    runButton.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        run = true;
        dialog.setVisible(false);
      }
    });
    buttonsPanel.add(runButton);

    JButton saveButton = new JButton("Save");
    saveButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        save(model);
      }
    });
    buttonsPanel.add(saveButton);
    dialog.add(buttonsPanel, BorderLayout.SOUTH);
    dialog.setModal(true);
    dialog.setResizable(true);
    dialog.add(actionsEditor.getComponent());
    dialog.pack();
    dialog.setLocationRelativeTo(topBottom);
    dialog.setVisible(true);
    if (!run) {
      System.exit(0);
      return;
    }
    Iterable<TaskFactory.Task> tasks = model.getTasks();
    executeTasks(tasks, model, "");
    tlPanel.format("Completed%n");
    RunLoader.singleton().stop();
  }

  /**
   * @param model
   */
  public void buildSomeActions(final Model model) {
    // Build some actions
    CA_Object ripe = model.getRootCA().findNode("RIPE-2");
    CA_Object lir1 = ripe.findNode("LIR-2");
    model.addAction(new AllocateAction(ripe, lir1, "a1", IPRangeType.ipv4, model, new Pair("p", 8)));
    String path = "UploadEpoch():byNode:UploadNode(IANA-0.RIPE-2.LIR-3):deleteFirst:UploadNodeFiles(IANA-0.RIPE-2.LIR-3):cer-mft-roa-crl:UploadGroupFiles(cer)";
    model.addAction(new ChooseCacheCheckTask(model, path));
  }

  protected void save(Model model) {
    while (fileChooser.showSaveDialog(getComponent()) == JFileChooser.APPROVE_OPTION) {
      File file = fileChooser.getSelectedFile();
      try {
        model.writeModel(file);
        return;
      } catch (IOException e) {
        Object[] msg = {
            e.getMessage(),
            "Try again?"
        };
        int option = JOptionPane.showConfirmDialog(getComponent(), msg, "Save Failed", JOptionPane.OK_CANCEL_OPTION);
        if (option != JOptionPane.OK_OPTION) {
          return;
        }
      }
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
   * @throws JDOMException
   */
  public static void main(String[] args) throws IOException, JDOMException {
    Main main = new Main(args);
    JFrame frame = new JFrame("Test Driver");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setContentPane(main.getComponent());
    frame.pack();
    frame.setLocationRelativeTo(null);
    frame.setVisible(true);
    main.run();
  }

}
