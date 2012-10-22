/*
 * Created on Oct 18, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.bbn.rpki.test.objects.Allocator;
import com.bbn.rpki.test.objects.CA_Object;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class InitializeAction {

  /**
   * @param model
   */
  public InitializeAction() {
  }

  private final List<AbstractAction> actions = new ArrayList<AbstractAction>();

  /**
   * @param action
   */
  public void addAction(AbstractAction action) {
    actions.add(action);
  }

  /**
   * For now, constrain sub-allocations to follow parent allocations
   * 
   * @param constraintActions
   */
  public List<AbstractAction> getActions(Allocator iana, List<AbstractAction> constraintActions) {
    constrainValidityStartTimes(iana, constraintActions);
    return actions;
  }

  private void constrainValidityStartTimes(Allocator iana, List<AbstractAction> constraintActions) {
    Map<CA_Object, AllocateAction> rcvdAllocations = new HashMap<CA_Object, AllocateAction>();
    for (AbstractAction action : actions) {
      if (action instanceof AllocateAction) {
        AllocateAction allocateAction = (AllocateAction) action;
        CA_Object rcvr = allocateAction.getChild();
        rcvdAllocations.put(rcvr, allocateAction);
      }
    }
    for (AbstractAction action : actions) {
      if (action instanceof AllocateActionBase) {
        AllocateActionBase allocateAction = (AllocateActionBase) action;
        Allocator parent = allocateAction.getParent();
        if (parent == iana) {
          // Validity start is not constrained
        } else {
          AllocateAction rcvdAction = rcvdAllocations.get(parent);
          rcvdAction.getValidityStartEvent().addSuccessor(allocateAction.getValidityStartEvent(), true);
          rcvdAction.getValidityEndEvent().addPredecessor(allocateAction.getValidityEndEvent(), true);
        }
        for (AbstractAction constraintAction : constraintActions) {
          allocateAction.constrainBy(constraintAction.getAllEpochEvents());
        }
      }
    }
  }
}
