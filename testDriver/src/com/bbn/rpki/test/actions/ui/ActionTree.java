/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.EpochEvent;
import com.bbn.rpki.test.tasks.Epoch;
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
        Enumeration<TreePath> expandedDescendents = actionTree.getExpandedDescendants(new TreePath(actionTreeModel.getRoot()));
        TreePath selectionPath = actionTree.getSelectionPath();
        List<EpochEvent> visibleEpochEvents = new ArrayList<EpochEvent>();
        if (expandedDescendents != null) {
          while (expandedDescendents.hasMoreElements()) {
            TreePath treePath = expandedDescendents.nextElement();
            Object last = treePath.getLastPathComponent();
            if (last instanceof Epoch) {
              visibleEpochEvents.addAll(((Epoch) last).getEpochEvents());
            }
          }
        }

        actionTreeModel.update(ActionTree.this.model);

        for (EpochEvent epochEvent : visibleEpochEvents) {
          TreePath path = actionTreeModel.findPathTo(epochEvent.getEpoch());
          actionTree.expandPath(path);
        }
        if (selectionPath != null) {
          Object lastComponent = selectionPath.getLastPathComponent();
          if (lastComponent instanceof EpochEvent) {
            // Try to re-select the same epoch after shuffling epochs
            TreePath newPath = actionTreeModel.findPathTo(lastComponent);
            actionTree.setSelectionPath(newPath);
            l.selectionChanged(newPath);
          }
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

  /**
   * @param addedAction
   */
  public void expandAndSelect(AbstractAction addedAction) {
    Collection<EpochEvent> allEpochEvents = addedAction.getAllEpochEvents();
    TreePath[] paths = new TreePath[allEpochEvents.size()];
    int ix = 0;
    for (EpochEvent epochEvent : allEpochEvents) {
      TreePath treePath = actionTreeModel.getPathToRoot();
      paths[ix++] = treePath;
    }
    actionTree.setSelectionPaths(paths);
  }
}
