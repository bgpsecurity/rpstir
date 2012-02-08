/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;

import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.EpochActions;
import com.bbn.rpki.test.actions.ui.ActionTree.SelectionListener;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ActionsEditor implements SelectionListener {
  private final JSplitPane splitPane;
  private final ActionTree actionTree;
  private final JScrollPane treePane;
  private final ActionDetail actionDetail;
  private TreePath selectedPath = null;
  private final Action insertAction = new javax.swing.AbstractAction("Insert") {
    @Override
    public void actionPerformed(ActionEvent e) {
      assert selectedPath != null;
      int pathCount = selectedPath.getPathCount();
      if (pathCount >= 2) {
        EpochActions epochActions = (EpochActions) selectedPath.getPathComponent(1);
        if (pathCount == 2) {
          actionTree.insertEpochBefore(epochActions);
        } else {
          assert pathCount == 3;
          AbstractAction action = (AbstractAction) selectedPath.getPathComponent(2);
          actionTree.insertActionBefore(epochActions, action);
        }
      }
    }
  };

  private final Action addAction = new javax.swing.AbstractAction("Add") {
    @Override
    public void actionPerformed(ActionEvent e) {
      assert selectedPath != null;
      int pathCount = selectedPath.getPathCount();
      if (pathCount >= 1) {
        if (pathCount == 1) {
          actionTree.addEpoch();
        } else {
          assert pathCount == 2;
          EpochActions epochActions = (EpochActions) selectedPath.getPathComponent(1);
          actionTree.addAction(epochActions);
        }
      }
    }
  };

  private final Action deleteAction = new javax.swing.AbstractAction("Delete") {
    @Override
    public void actionPerformed(ActionEvent e) {
      assert selectedPath != null;
      int pathCount = selectedPath.getPathCount();
      if (pathCount >= 2) {
        EpochActions epochActions = (EpochActions) selectedPath.getPathComponent(1);
        if (pathCount == 2) {
          actionTree.deleteEpoch(epochActions);
        } else {
          assert pathCount == 3;
          AbstractAction action = (AbstractAction) selectedPath.getPathComponent(2);
          actionTree.deleteAction(epochActions, action);
        }
      }
    }
  };

  /**
   * @param model
   */
  public ActionsEditor(Model model) {
    actionTree = new ActionTree(model, this);
    actionDetail = new ActionDetail(model);
    treePane = new JScrollPane(actionTree.getComponent());
    JPanel treePanel = new JPanel(new BorderLayout());
    treePanel.add(treePane);
    JPanel treeButtons = new JPanel();
    JButton[] buttons = {
        new JButton(addAction),
        new JButton(insertAction),
        new JButton(deleteAction)
    };
    for (JButton jButton : buttons) {
      treeButtons.add(jButton);
    }
    treePanel.add(treeButtons, BorderLayout.SOUTH);
    splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treePanel, actionDetail.getComponent());
    splitPane.setDividerLocation(0.5);
    splitPane.setResizeWeight(0.5);
    splitPane.setPreferredSize(new Dimension(800, 600));
    selectionChanged(null);
  }

  /**
   * @return the GUI component
   */
  public Component getComponent() {
    return splitPane;
  }

  private void changeAction(Action action, String name) {
    if (name == null) {
      action.setEnabled(false);
    } else {
      action.putValue(Action.NAME, name);
      action.setEnabled(true);
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.ui.ActionTree.SelectionListener#selectionChanged(javax.swing.tree.TreePath)
   */
  @Override
  public void selectionChanged(TreePath newPath) {
    selectedPath = newPath;
    int pathCount;
    if (newPath != null) {
      pathCount = newPath.getPathCount();
    } else {
      pathCount = 0;
    }
    if (pathCount > 2) {
      AbstractAction action = (AbstractAction) newPath.getPathComponent(2);
      actionDetail.setAction(action);
      changeAction(insertAction, "Insert Action");
      changeAction(deleteAction, "Delete Action");
      changeAction(addAction, null);
    } else if (pathCount > 1) {
      changeAction(insertAction, "Insert Epoch");
      changeAction(deleteAction, "Delete Epoch");
      changeAction(addAction, "Add Action");
    } else {
      changeAction(insertAction, null);
      changeAction(deleteAction, null);
      if (pathCount > 0) {
        changeAction(addAction, "Add Epoch");
      } else {
        changeAction(addAction, null);
      }
    }
  }
}
