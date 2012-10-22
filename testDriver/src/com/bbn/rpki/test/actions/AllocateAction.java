/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;

import org.jdom.Element;

import com.bbn.rpki.test.objects.AllocationId;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.TypedPair;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Represents an allocation action to be performed as part of a test.
 *
 * @author tomlinso
 */
public class AllocateAction extends AllocateActionBase {

  private CA_Object child;

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param rangeType
   * @param model
   * @param pairs the ranges or prefixes to be allocated
   */
  public AllocateAction(CA_Object parent, CA_Object child, AllocationId allocationId, Model model, TypedPair...pairs) {
    super(parent, allocationId, model, pairs);
    this.child = child;
  }

  /**
   * Default constructor must have a model to make any sense
   * @param model
   */
  public AllocateAction(Model model) {
    this(model.getRootCA(), model.getRootCA().getChild(0), AllocationId.generate(), model);
  }

  /**
   * Constructor from xml Element
   * @param element
   * @param model
   * @param actionContext
   */
  public AllocateAction(Element element, Model model, ActionContext actionContext) {
    super(element, model, actionContext);
    String childName = element.getAttributeValue(ATTR_CHILD_NAME);
    child = ActionManager.singleton().findCA_Object(childName);
  }

  /**
   * @return an element encoding this action
   */
  @Override
  public Element toXML(ActionContext actionContext) {
    Element element = createElement(ActionType.allocate);
    super.appendXML(element, actionContext);
    element.setAttribute(ATTR_CHILD_NAME, child.commonName);
    return element;
  }

  /**
   * Perform the allocation described
   * 
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(EpochEvent, TypescriptLogger)
   */
  @Override
  public void execute(EpochEvent epochEvent, TypescriptLogger logger) {
    switch (epochEvent.getName()) {
    case PUBLICATION_TIME_OF_ALLOCATION:
      for (TypedPair typedPair : allocationPairs) {
        switch (typedPair.type) {
        case ipv4:
          child.takeIPv4(Collections.singletonList(typedPair), allocationId);
          break;
        case ipv6:
          child.takeIPv6(Collections.singletonList(typedPair), allocationId);
          break;
        case as:
          child.takeAS(Collections.singletonList(typedPair), allocationId);
          break;
        }
      }
      if (logger != null) {
        logger.format("Allocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
      }
      break;
    case VALIDITY_END_TIME_OF_ALLOCATION:
      child.returnAllocation(allocationId);
      if (logger != null) {
        logger.format("Deallocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
      }
      break;
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#addExecutionTime(com.bbn.rpki.test.actions.EpochEvent, com.bbn.rpki.test.actions.ExecutionTimeContext)
   */
  @Override
  public void addExecutionTime(EpochEvent epochEvent, ExecutionTimeContext etContext) {
    switch (epochEvent.getName()) {
    case PUBLICATION_TIME_OF_ALLOCATION:
    case PUBLICATION_TIME_OF_DEALLOCATION:
      etContext.publishCert(parent, child);
      break;
    default:
      // Nothing to do for other epoch events
      break;
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  protected void maybePutSubject(LinkedHashMap<String, Object> ret) {
    ret.put(AttributeType.SUBJECT.getDisplayName(), child);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getId()
   */
  @Override
  public AllocationId getId() {
    return allocationId;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Allocate %s: %s from %s to %s", allocationId, allocationPairs, parent.getNickname(), child.getNickname());
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#updateAttribute(java.lang.String, java.lang.Object)
   */
  @Override
  public void updateAttribute(String label, Object newValue) {
    AttributeType at = AttributeType.forDisplayName(label);
    switch (at) {
    case SUBJECT:
      child = (CA_Object) newValue;
      break;
    default:
      super.updateAttribute(label, newValue);
      break;
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getExecutionEpochs()
   */
  @Override
  public Collection<EpochEvent> getExecutionEpochs() {
    return Arrays.asList(allocationPublicationTime, deallocationPublicationTime);
  }

  /**
   * Constraint out epoch events to precede or follow the given events
   * @param otherEpochEvents
   */
  @Override
  public void constrainBy(Collection<EpochEvent> otherEpochEvents) {
    for (EpochEvent epochEvent : otherEpochEvents) {
      allocationPublicationTime.addSuccessor(epochEvent, true);
      validityStartTime.addSuccessor(epochEvent, true);
      deallocationPublicationTime.addPredecessor(epochEvent, true);
      validityEndTime.addPredecessor(epochEvent, true);
    }
  }

  /**
   * @return
   */
  public CA_Object getChild() {
    return child;
  }
}
