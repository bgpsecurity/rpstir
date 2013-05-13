/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import org.jdom.Element;

import com.bbn.rpki.test.objects.AllocationId;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeList;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Range;
import com.bbn.rpki.test.objects.TypedPair;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Represents an allocation action to be performed as part of a test.
 * 
 * There are four epoch events associated with an allocation action:
 *   Validity start time -- when the allocation becomes effective
 *   validity start publication time -- when the certificate containg the allocation is published
 *   validity end time -- when the allocation ceases to be in effect
 *   validity end publication time -- when the certificate containing the allocation is revoked
 * This would seem to imply that allocations have a planned lifetime, but they don't. For testing,
 * however, it is necessary to cover the cases where an allocation is rescinded and the associated
 * timing of when the world becomes aware of this.
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
    this(model.getRootCA(), getFirstChild(model), AllocationId.generate(), model);
  }

  private static CA_Object getFirstChild(Model model) {
    CA_Object rootCA = model.getRootCA();
    if (rootCA.getChildCount() == 0) {
      return rootCA;
    }
    return rootCA.getChild(0);
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
    element.setAttribute(ATTR_CHILD_NAME, child.getCommonName());
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
      if (child == parent || parent == null) {
        // root, gets all
        child.addRcvdRanges(validityStartTime.getEpoch().getEpochTime(),
                            validityEndTime.getEpoch().getEpochTime(),
                            allocationId,
                            getEverything(IPRangeType.as),
                            getEverything(IPRangeType.ipv4),
                            getEverything(IPRangeType.ipv6));
      } else {
        for (TypedPair typedPair : allocationPairs) {
          switch (typedPair.type) {
          case ipv4:
            child.takeAllocation(Collections.singletonList(typedPair),
                                 IPRangeType.ipv4,
                                 validityStartTime.getEpoch().getEpochTime(),
                                 validityEndTime.getEpoch().getEpochTime(),
                                 allocationId);
            break;
          case ipv6:
            child.takeAllocation(Collections.singletonList(typedPair),
                                 IPRangeType.ipv6,
                                 validityStartTime.getEpoch().getEpochTime(),
                                 validityEndTime.getEpoch().getEpochTime(),
                                 allocationId);
            break;
          case as:
            child.takeAllocation(Collections.singletonList(typedPair),
                                 IPRangeType.as,
                                 validityStartTime.getEpoch().getEpochTime(),
                                 validityEndTime.getEpoch().getEpochTime(),
                                 allocationId);
            break;
          }
        }
        if (logger != null) {
          logger.format("Allocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
        }
      }
      break;
    case VALIDITY_END_TIME_OF_ALLOCATION:
      if (child != parent) {
        child.returnAllocation(allocationId);
        if (logger != null) {
          logger.format("Deallocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
        }
      }
      break;
    }
  }


  private IPRangeList getEverything(IPRangeType rangeType) {
    IPRangeList everything = new IPRangeList(rangeType);
    everything.add(new Range(BigInteger.ZERO, rangeType.getMax(), rangeType, rangeType == IPRangeType.as));
    return everything;
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
    String parentNickname = parent == null ? "<unspecified>" : parent.getNickname();
    String childNickname = child == null ? "<unspecified>" : child.getNickname();
    return String.format("Allocate %s: %s from %s to %s", allocationId, allocationPairs, parentNickname, childNickname);
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
    case ISSUER:
      super.updateAttribute(label, newValue);
      // Child must be child of new issuer
      if (child.getParent() != newValue) {
        child = null;
      }
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
   * @return he child CA_Object
   */
  public CA_Object getChild() {
    return child;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#referencesCA(com.bbn.rpki.test.objects.CA_Object)
   */
  @Override
  public boolean referencesCA(CA_Object caObject) {
    return caObject == getChild() || caObject == getParent();
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getInvalidReasons()
   */
  @Override
  public List<String> getInvalidReasons() {
    List<String> ret = super.getInvalidReasons();
    if (getParent() == null && getParent() != model.getRootCA()) {
      ret = appendReason(ret, "Issuer CA must be specified");
    }
    if (child == null) {
      ret = appendReason(ret, "Subject CA must be specified");
    }
    CA_Object childParent = child.getParent();
    if (childParent != null && childParent != child) {
      if (childParent != getParent()) {
        ret = appendReason(ret, "Subject CA must be a child of the issuer CA");
      }
    }
    return ret;
  }
}
