/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;
import java.lang.reflect.Constructor;

import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.AllocateAction;
import com.bbn.rpki.test.actions.ChooseCacheCheckTask;
import com.bbn.rpki.test.actions.DeallocateAction;
import com.bbn.rpki.test.actions.EpochActions;
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
    actionTree.addTreeSelectionListener(new TreeSelectionListener() {

      @Override
      public void valueChanged(TreeSelectionEvent e) {
        TreePath path = e.getNewLeadSelectionPath();
        l.selectionChanged(path);
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
   * Insert an epoch before the selected epoch
   * @param beforeEpoch
   */
  public void insertEpochBefore(EpochActions beforeEpoch) {
    actionTreeModel.insertEpochBefore(beforeEpoch);
  }

  /**
   * Add an epoch to the end
   */
  public void addEpoch() {
    EpochActions epochActions = actionTreeModel.addEpoch();
    Object[] path = {actionTreeModel.getRoot(), epochActions};
    actionTree.setSelectionPath(new TreePath(path));
  }

  /**
   * Insert an action before the selected action
   * @param epochActions
   * @param beforeAction
   */
  public void insertActionBefore(EpochActions epochActions, AbstractAction beforeAction) {
    AbstractAction action = createAction();
    if (action != null) {
      actionTreeModel.insertActionBefore(epochActions, beforeAction, action);
      Object[] path = {actionTreeModel.getRoot(), epochActions, action};
      actionTree.setSelectionPath(new TreePath(path));
    }
  }

  /**
   * Add an epoch to the end
   * @param epochActions
   */
  public void addAction(EpochActions epochActions) {
    AbstractAction action = createAction();
    if (action != null) {
      actionTreeModel.addAction(epochActions, action);
      Object[] path = {actionTreeModel.getRoot(), epochActions, action};
      actionTree.setSelectionPath(new TreePath(path));
    }
  }

  /**
   * Delete the epoch
   * @param epochActions
   * @param actionToDelete
   */
  public void deleteAction(EpochActions epochActions, AbstractAction actionToDelete) {
    actionTreeModel.removeAction(epochActions, actionToDelete);
  }

  /**
   * Delete the action
   * @param epochActions
   */
  public void deleteEpoch(EpochActions epochActions) {
    actionTreeModel.removeEpoch(epochActions);
  }

  private AbstractAction createAction() {
    Class<?>[] classes = {
        AllocateAction.class,
        DeallocateAction.class,
        ChooseCacheCheckTask.class
    };
    String[] names = new String[classes.length];
    for (int i = 0; i < names.length; i++) {
      names[i] = classes[i].getSimpleName();
    }
    JComboBox box = new JComboBox(names);
    int option = JOptionPane.showConfirmDialog(actionTree, box, "Select a Type of Action", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
    if (option == JOptionPane.OK_OPTION) {
      int index = box.getSelectedIndex();
      if (index >= 0) {
        Class<?> chosenClass = classes[index];
        try {
          Constructor<?> constructor = chosenClass.getConstructor(Model.class);
          return (AbstractAction) constructor.newInstance(model);
        } catch (Exception e) {
          return null;
        }
      }
    }
    return null;
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
