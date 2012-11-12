/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.tasks.Model;

/**
 * Provides a dialog for selecting a CA.
 * The dialog displays the CA hierarchy as a tree
 *
 * @author tomlinso
 */
public class CAChooser implements TreeSelectionListener {
  interface Listener {
    void selectionChanged(CA_Object caObject);
  }

  private final CATreeModel treeModel;
  private final JTree tree;
  private final JTextField nicknameField = new JTextField();
  private final JTextField serverNameField = new JTextField();
  private CA_Object selectedCA;
  private final JScrollPane scrollPane;
  private final List<Listener> listeners = new ArrayList<Listener>(1);
  private final Model model;

  /**
   * @param model
   * @param ca
   * @param newCA
   */
  public CAChooser(Model model, CA_Object ca) {
    this.model = model;
    CA_Object rootCA = model.getRootCA();
    treeModel = new CATreeModel(rootCA);
    tree = new JTree(treeModel);
    tree.addTreeSelectionListener(this);
    if (ca != null) {
      selectCA(ca);
    }
    scrollPane = new JScrollPane(tree);
  }

  /**
   * @param ca
   */
  public void selectCA(CA_Object ca) {
    CA_Object[] path = getPathToRoot((CA_Object) treeModel.getRoot(), ca, 0);
    tree.setSelectionPath(new TreePath(path));
  }

  public Component getComponent() {
    return scrollPane;
  }

  /**
   * @param ca
   * @param depth
   * @return
   */
  private CA_Object[] getPathToRoot(CA_Object rootCA, CA_Object ca, int depth) {
    CA_Object[] ret;
    if (ca == rootCA) {
      ret = new CA_Object[depth + 1];
    } else {
      ret = getPathToRoot(rootCA, ca.getParent(), depth + 1);
    }
    ret[ret.length - depth - 1] = ca;
    return ret;
  }

  /**
   * @param c
   * @return the selected CA_Object or null for no selection
   */
  public CA_Object showDialog(Component c) {
    Object[] options;
    options = new Object[] {
        "Ok",
        "Cancel",
        "New CA..."
    };
    while (true) {
      JOptionPane optionPane =
          new JOptionPane(scrollPane,
                          JOptionPane.QUESTION_MESSAGE,
                          JOptionPane.DEFAULT_OPTION,
                          null, options, null);
      JDialog dialog = optionPane.createDialog(c, "Select a CA");
      dialog.setResizable(true);
      dialog.setVisible(true);
      dialog.dispose();
      Object value = optionPane.getValue();
      // Should be String unless aborted
      if (value == null || value == options[1]) {
        return null;
      }
      if (value == options[0]) {
        return selectedCA;
      }
      if (value == options[1]) {
        return null;
      }
      CAEditor caEditor = new CAEditor(model, selectedCA, scrollPane);
      CA_Object caObject = caEditor.showDialog();
      treeModel.update();
      selectCA(caObject);
    }
  }

  /**
   * @param caObject
   * @return
   */
  private String getServerName(CA_Object caObject) {
    while (!caObject.isBreakAway() && caObject.getParent() != null) {
      caObject = caObject.getParent();
    }
    return caObject.getServerName();
  }

  /**
   * @see javax.swing.event.TreeSelectionListener#valueChanged(javax.swing.event.TreeSelectionEvent)
   */
  @Override
  public void valueChanged(TreeSelectionEvent e) {
    TreePath selectionPath = tree.getSelectionPath();
    selectedCA = selectionPath != null ? (CA_Object) selectionPath.getLastPathComponent() : null;
    if (selectedCA != null) {
      serverNameField.setText(getServerName(selectedCA));
    }
    for (Listener l : new ArrayList<Listener>(listeners)) {
      l.selectionChanged(selectedCA);
    }
  }

  /**
   * @param l
   */
  public void addListener(Listener l) {
    listeners.add(l);
    l.selectionChanged(selectedCA);
  }

  /**
   * 
   */
  public void update() {
    treeModel.update();
  }
}
