/*
 * Created on Feb 3, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.objects.CA_Object;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class CATreeModel implements TreeModel {

  private final CA_Object rootCA;
  private final List<TreeModelListener> listeners =
    new ArrayList<TreeModelListener>(1);

  /**
   * @param rootCA
   */
  public CATreeModel(CA_Object rootCA) {
    this.rootCA = rootCA;
  }

  /**
   * @see javax.swing.tree.TreeModel#getRoot()
   */
  @Override
  public Object getRoot() {
    return rootCA;
  }

  /**
   * @see javax.swing.tree.TreeModel#getChild(java.lang.Object, int)
   */
  @Override
  public Object getChild(Object parent, int index) {
    CA_Object p = (CA_Object) parent;
    return p.getChild(index);
  }

  /**
   * @see javax.swing.tree.TreeModel#getChildCount(java.lang.Object)
   */
  @Override
  public int getChildCount(Object parent) {
    CA_Object p = (CA_Object) parent;
    return p.getChildCount();
  }

  /**
   * @see javax.swing.tree.TreeModel#isLeaf(java.lang.Object)
   */
  @Override
  public boolean isLeaf(Object node) {
    // There are no leaf nodes
    return false;
  }

  /**
   * @see javax.swing.tree.TreeModel#valueForPathChanged(javax.swing.tree.TreePath, java.lang.Object)
   */
  @Override
  public void valueForPathChanged(TreePath path, Object newValue) {
    // Nothing to do
  }

  /**
   * @see javax.swing.tree.TreeModel#getIndexOfChild(java.lang.Object, java.lang.Object)
   */
  @Override
  public int getIndexOfChild(Object parent, Object child) {
    CA_Object p = (CA_Object) parent;
    CA_Object c = (CA_Object) child;
    return p.indexOf(c);
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

}
