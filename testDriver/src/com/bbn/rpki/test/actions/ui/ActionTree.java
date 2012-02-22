/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;

import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import com.bbn.rpki.test.actions.Epoch;
import com.bbn.rpki.test.tasks.Model;

/**
 * Displays a two-level tree of epochs and actions in epochs
 *
 * @author tomlinso
 */
public class ActionTree {
  interface SelectionListener {
    void selectionChanged(TreePath newPath);
  }
  private final JTree actionTree;
  private final ActionTreeModel actionTreeModel;
  private final Model model;

  /**
   * @param model
   * @param l
   */
  public ActionTree(Model model, final SelectionListener l) {
    this.model = model;
    this.actionTreeModel = new ActionTreeModel(model);
    actionTree = new JTree(actionTreeModel);
    for (int i = 0; i < actionTree.getRowCount(); i++) {
      actionTree.expandRow(i);
    }
    actionTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
    actionTree.addTreeSelectionListener(new TreeSelectionListener() {

      @Override
      public void valueChanged(TreeSelectionEvent e) {
        TreePath path = e.getNewLeadSelectionPath();
        l.selectionChanged(path);
      }
    });
    model.addListener(new Model.Listener() {

      @Override
      public void epochsChanged() {
        // Save the current selection and try to re-establish after changing the model
        TreePath path = actionTree.getSelectionPath();
        actionTreeModel.update(ActionTree.this.model);
        Object lastComponent = path.getLastPathComponent();
        if (lastComponent instanceof Epoch) {
          // Try to re-select the same epoch after shuffling epochs
          TreePath newPath = actionTreeModel.findPathTo(lastComponent);
          actionTree.setSelectionPath(newPath);
          l.selectionChanged(newPath);
        }
      }
    });
  }

  /**
   * @return the GUI component
   */
  public Component getComponent() {
    return actionTree;
  }

  /**
   * Expand everything
   */
  public void expand() {
    for (int i = 0; i < actionTree.getRowCount(); i++) {
      actionTree.expandRow(i);
    }
  }

  /**
   * Collapse everything
   */
  public void collapse() {
    for (int i = 0; i < actionTree.getRowCount(); i++) {
      actionTree.collapseRow(i);
    }
  }
}
