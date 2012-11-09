/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.AllocationId;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.EE_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.Roa;
import com.bbn.rpki.test.objects.TypedPair;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Represents an allocation action to be performed as part of a test.
 *
 * @author tomlinso
 */
public class AllocateROAAction extends AllocateActionBase {

  private EE_Object eeObject;

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param model
   * @param pairs the ranges or prefixes to be allocated
   */
  public AllocateROAAction(CA_Object parent, AllocationId allocationId, Model model, TypedPair...pairs) {
    super(parent, allocationId, model, pairs);
  }

  /**
   * Default constructor must have a model to make any sense
   * @param model
   */
  public AllocateROAAction(Model model) {
    this(model.getRootCA(), AllocationId.get("roa"), model);
  }

  /**
   * Constructor from xml Element
   * @param element
   * @param model
   * @param actionContext
   */
  public AllocateROAAction(Element element, Model model, ActionContext actionContext) {
    super(element, model, actionContext);
  }

  /**
   * @return an element encoding this action
   */
  @Override
  public Element toXML(ActionContext actionContext) {
    Element element = createElement(ActionType.allocateROA);
    super.appendXML(element, actionContext);
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
      List<Pair> asid = Collections.singletonList(new Pair("r", 1));
      eeObject = new EE_Object(validityStartTime.getEpoch().getEpochTime(),
                               validityEndTime.getEpoch().getEpochTime(),
                               asid,
                               allocationPairs.extract(IPRangeType.ipv4),
                               allocationPairs.extract(IPRangeType.ipv6),
                               "ROA-" + allocationId,
                               parent);
      Roa roa = new Roa(eeObject);
      if (logger != null) {
        logger.format("Allocate ROA %s from %s to %s identified as %s%n", allocationPairs, parent, eeObject, allocationId);
      }
      break;
    case VALIDITY_END_TIME_OF_ALLOCATION:
      eeObject.returnAllocation();
      if (logger != null) {
        logger.format("Deallocate ROA %s from %s to %s identified as %s%n", allocationPairs, parent, eeObject, allocationId);
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
      //      etContext.publishCert(parent, child);
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
  public Map<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.ALLOCATION_ID.getDisplayName(), allocationId);
    ret.put(AttributeType.ISSUER.getDisplayName(), parent);
    //    ret.put(AttributeType.SUBJECT.getDisplayName(), child);
    ret.put(AttributeType.ALLOCATION_PUBLICATION_TIME.getDisplayName(), allocationPublicationTime);
    ret.put(AttributeType.VALIDITY_START_TIME.getDisplayName(), validityStartTime);
    ret.put(AttributeType.DEALLOCATION_PUBLICATION_TIME.getDisplayName(), deallocationPublicationTime);
    ret.put(AttributeType.VALIDITY_END_TIME.getDisplayName(), validityEndTime);
    ret.put(AttributeType.ALLOCATIONS.getDisplayName(), allocationPairs);
    return ret;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Allocate ROA %s: %s from %s", allocationId, allocationPairs, parent.getNickname());
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#referencesCA(com.bbn.rpki.test.objects.CA_Object)
   */
  @Override
  public boolean referencesCA(CA_Object caObject) {
    return caObject == getParent();
  }
}
