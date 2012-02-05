/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.EpochActions;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ActionTreeModel implements TreeModel {
  class EpochsNode {
    List<EpochActions> epochs;
    EpochsNode(List<EpochActions> epochs) {
      this.epochs = epochs;
    }
    @Override
    public String toString() {
      return "Epochs";
    }
  }
  private final EpochsNode epochsNode;
  private final List<TreeModelListener> listeners = new ArrayList<TreeModelListener>(1);

  /**
   * @param model
   */
  public ActionTreeModel(Model model) {
    int epochCount = model.getEpochCount();
    List<EpochActions> list = new ArrayList<EpochActions>(epochCount);
    for (int i = 1; i < epochCount; i++) {
      list.add(model.getEpochActions(i));
    }
    epochsNode = new EpochsNode(list);
  }

  /**
   * @see javax.swing.tree.TreeModel#getRoot()
   */
  @Override
  public Object getRoot() {
    return epochsNode;
  }

  /**
   * @see javax.swing.tree.TreeModel#getChild(java.lang.Object, int)
   */
  @Override
  public Object getChild(Object parent, int index) {
    if (parent == epochsNode) {
      return epochsNode.epochs.get(index);
    }
    if (parent instanceof EpochActions) {
      EpochActions epochActions = (EpochActions) parent;
      return epochActions.getAction(index);
    }
    // No more non-leaf nodes
    return null;
  }

  /**
   * @see javax.swing.tree.TreeModel#getChildCount(java.lang.Object)
   */
  @Override
  public int getChildCount(Object parent) {
    if (parent == epochsNode) {
      return epochsNode.epochs.size();
    }
    if (parent instanceof EpochActions) {
      EpochActions epochActions = (EpochActions) parent;
      return epochActions.getActionCount();
    }
    return 0;
  }

  /**
   * @see javax.swing.tree.TreeModel#isLeaf(java.lang.Object)
   */
  @Override
  public boolean isLeaf(Object node) {
    if (node == epochsNode) {
      return false;
    }
    if (node instanceof EpochActions) {
      return false;
    }
    return true;
  }

  /**
   * @see javax.swing.tree.TreeModel#valueForPathChanged(javax.swing.tree.TreePath, java.lang.Object)
   */
  @Override
  public void valueForPathChanged(TreePath path, Object newValue) {
    // No tree editing yet
  }

  /**
   * @see javax.swing.tree.TreeModel#getIndexOfChild(java.lang.Object, java.lang.Object)
   */
  @Override
  public int getIndexOfChild(Object parent, Object child) {
    if (parent == epochsNode) {
      EpochActions ae = (EpochActions) child;
      return epochsNode.epochs.indexOf(ae);
    }
    if (parent instanceof EpochActions) {
      EpochActions ae = (EpochActions) parent;
      return ae.indexOf(child);
    }
    return -1;
  }

  /**
   * @see javax.swing.tree.TreeModel#addTreeModelListener(javax.swing.event.TreeModelListener)
   */
  @Override
  public void addTreeModelListener(TreeModelListener l) {
    listeners.add(l);
  }

  /**
   * @see javax.swing.tree.TreeModel#removeTreeModelListener(javax.swing.event.TreeModelListener)
   */
  @Override
  public void removeTreeModelListener(TreeModelListener l) {
    listeners.remove(l);
  }

  private void fireTreeNodesInserted(int index, Object child, Object... path) {
    int[] childIndexes = {index};
    Object[] children = {child};
    TreeModelEvent e = new TreeModelEvent(this, path, childIndexes, children);
    for (TreeModelListener l : listeners) {
      l.treeNodesInserted(e);
    }
  }

  private void fireTreeNodesRemoved(int index, Object child, Object... path) {
    int[] childIndexes = {index};
    Object[] children = {child};
    TreeModelEvent e = new TreeModelEvent(this, path, childIndexes, children);
    for (TreeModelListener l : listeners) {
      l.treeNodesRemoved(e);
    }
  }

  /**
   * @param epochActions
   * @param actionToRemove
   */
  public void removeAction(EpochActions epochActions, AbstractAction actionToRemove) {
    int index = epochActions.indexOf(actionToRemove);
    epochActions.removeAction(index);
    fireTreeNodesRemoved(index, actionToRemove, epochsNode, epochActions);
  }

  /**
   * @param epochActions
   * @param action
   * @param index
   */
  public void addAction(EpochActions epochActions, AbstractAction action, int index) {
    epochActions.addAction(index, action);
    fireTreeNodesInserted(index, action, epochsNode, epochActions);
  }

  /**
   * @param epochToRemove
   */
  public void removeEpoch(EpochActions epochToRemove) {
    int index = epochsNode.epochs.indexOf(epochToRemove);
    epochsNode.epochs.remove(index);
    fireTreeNodesRemoved(index, epochToRemove, epochsNode);
  }

  /**
   * @param epochActions
   */
  public void insertEpochBefore(EpochActions epochActions) {
    int index = epochsNode.epochs.indexOf(epochActions);
    insertEpoch(index);
  }

  /**
   * Append a new epoch
   * @return the added EpochActions
   */
  public EpochActions addEpoch() {
    int index = epochsNode.epochs.size();
    return insertEpoch(index);
  }

  /**
   * @param index
   * @return
   */
  private EpochActions insertEpoch(int index) {
    EpochActions newEpochActions = new EpochActions(index);
    epochsNode.epochs.add(index, newEpochActions);
    fireTreeNodesInserted(index, newEpochActions, epochsNode);
    return newEpochActions;
  }

  /**
   * @param epochActions
   * @param selectedAction
   * @param action
   */
  public void insertActionBefore(EpochActions epochActions, AbstractAction selectedAction,
                                 AbstractAction action) {
    int index = epochActions.indexOf(selectedAction);
    epochActions.addAction(index, action);
    fireTreeNodesInserted(index, action, epochsNode, epochActions);
  }

  /**
   * @param epochActions
   * @param action
   */
  public void addAction(EpochActions epochActions, AbstractAction action) {
    int index = epochActions.getActionCount();
    epochActions.addAction(index, action);
    fireTreeNodesInserted(index, action, epochsNode, epochActions);
  }
}
