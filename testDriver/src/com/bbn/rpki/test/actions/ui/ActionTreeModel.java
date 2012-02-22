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

import com.bbn.rpki.test.tasks.EpochGroup;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ActionTreeModel implements TreeModel {
  class EpochsNode {
    List<EpochGroup> epochs;

    @Override
    public String toString() {
      return "Epochs";
    }
  }
  private final EpochsNode epochsNode = new EpochsNode();
  private final List<TreeModelListener> listeners = new ArrayList<TreeModelListener>(1);

  /**
   * @param model
   */
  public ActionTreeModel(Model model) {
    update(model);
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
    if (parent instanceof EpochGroup) {
      EpochGroup epochGroup = (EpochGroup) parent;
      return epochGroup.getEpoch(index);
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
    if (parent instanceof EpochGroup) {
      EpochGroup epochGroup = (EpochGroup) parent;
      return epochGroup.getEpochCount();
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
    if (node instanceof EpochGroup) {
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
      return epochsNode.epochs.indexOf(child);
    }
    if (parent instanceof EpochGroup) {
      EpochGroup ae = (EpochGroup) parent;
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

  private void fireRootModified() {
    Object[] path = {getRoot()};
    TreeModelEvent e = new TreeModelEvent(this, path);
    for (TreeModelListener l : listeners) {
      l.treeStructureChanged(e);
    }
  }

  /**
   * @param model
   */
  public void update(Model model) {
    epochsNode.epochs = new ArrayList<EpochGroup>(model.getEpochGroups());
    fireRootModified();
  }

  /**
   * @param lastComponent
   * @return the path to the specified component
   */
  public TreePath findPathTo(Object lastComponent) {
    return findPathTo(new TreePath(getRoot()), lastComponent);
  }

  private TreePath findPathTo(TreePath parentPath, Object lastComponent) {
    for (int i = 0, n = getChildCount(parentPath.getLastPathComponent()); i < n; i++) {
      Object child = getChild(parentPath.getLastPathComponent(), i);
      TreePath treePath = parentPath.pathByAddingChild(child);
      if (child == lastComponent) {
        return treePath;
      }
      treePath = findPathTo(treePath, lastComponent);
      if (treePath != null) {
        return treePath;
      }
    }
    return null;
  }
}
