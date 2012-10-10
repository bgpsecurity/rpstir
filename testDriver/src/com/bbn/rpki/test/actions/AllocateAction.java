/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.PairList;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Represents an allocation action to be performed as part of a test.
 *
 * @author tomlinso
 */
public class AllocateAction extends AbstractAction {

  /**
   * 
   */
  private static final String VALIDITY_END_TIME_OF_ALLOCATION = "Validity End Time of Allocation ";
  /**
   * 
   */
  private static final String VALIDITY_START_TIME_OF_ALLOCATION = "Validity Start Time of Allocation ";
  /**
   * 
   */
  private static final String PUBLICATION_TIME_OF_DEALLOCATION = "Publication Time of Deallocation ";
  /**
   * 
   */
  private static final String PUBLICATION_TIME_OF_ALLOCATION = "Publication Time of Allocation ";

  enum AttributeType {
    INR_TYPE("INR Type"),
    ISSUER("Issuer"),
    SUBJECT("Subject"),
    ALLOCATION_PUBLICATION_TIME("Allocation Publication Time"),
    DEALLOCATION_PUBLICATION_TIME("Deallocation Publication Time"),
    VALIDITY_START_TIME("Validity Start Time"),
    VALIDITY_END_TIME("Validity End Time"),
    ALLOCATION_ID("Allocation Id"),
    ALLOCATIONS("Allocations");

    static Map<String, AttributeType> d2o = null;

    static AttributeType forDisplayName(String displayName) {
      if (d2o == null) {
        d2o = new HashMap<String, AttributeType>();
        for (AttributeType at : values()) {
          d2o.put(at.getDisplayName(), at);
        }
      }
      return d2o.get(displayName);
    }

    private String displayName;
    AttributeType(String displayName) {
      this.displayName = displayName;
    }
    public String getDisplayName() {
      return displayName;
    }

    @Override
    public String toString() {
      return getDisplayName();
    }
  }

  private PairList allocationPairs = new PairList();
  private CA_Object parent;
  private CA_Object child;
  private String allocationId;
  private IPRangeType rangeType;
  private final EpochEvent allocationPublicationTime;
  private final EpochEvent deallocationPublicationTime;
  private final EpochEvent validityStartTime;
  private final EpochEvent validityEndTime;

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param rangeType
   * @param model
   * @param pairs the ranges or prefixes to be allocated
   */
  public AllocateAction(CA_Object parent, CA_Object child, String allocationId, IPRangeType rangeType, Model model, Pair...pairs) {
    this.parent = parent;
    this.child = child;
    this.allocationId = allocationId;
    this.rangeType = rangeType;
    this.allocationPairs.addAll(Arrays.asList(pairs));
    allocationPublicationTime = new EpochEvent(this, PUBLICATION_TIME_OF_ALLOCATION);
    deallocationPublicationTime = new EpochEvent(this, PUBLICATION_TIME_OF_DEALLOCATION);
    validityStartTime = new EpochEvent(this, VALIDITY_START_TIME_OF_ALLOCATION);
    validityEndTime = new EpochEvent(this, VALIDITY_END_TIME_OF_ALLOCATION);
    // Constrain start before end always
    validityStartTime.addSuccessor(validityEndTime, true);
    // Constrain publication when validity changes as default
    validityStartTime.addCoincident(allocationPublicationTime, false);
    validityEndTime.addCoincident(deallocationPublicationTime, false);
  }

  /**
   * Default constructor must have a model to make any sense
   * @param model
   */
  public AllocateAction(Model model) {
    this(model.getRootCA(), model.getRootCA().getChild(0), "", IPRangeType.ipv4, model);
  }

  /**
   * Constructor from xml Element
   * @param element
   * @param model
   * @param actionContext
   */
  public AllocateAction(Element element, Model model, ActionContext actionContext) {
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_NAME);
    String childName = element.getAttributeValue(ATTR_CHILD_NAME);
    allocationId = element.getAttributeValue(ATTR_ALLOCATION_ID);
    String rangeTypeName = element.getAttributeValue(ATTR_RANGE_TYPE);

    parent = ActionManager.singleton().findCA_Object(parentCommonName);
    child = ActionManager.singleton().findCA_Object(childName);
    rangeType = IPRangeType.valueOf(rangeTypeName);

    Element allocationPublicationTimeElement = element.getChild(AttributeType.ALLOCATION_PUBLICATION_TIME.name());
    Element deallocationPublicationTimeElement = element.getChild(AttributeType.DEALLOCATION_PUBLICATION_TIME.name());
    Element validityStartTimeElement = element.getChild(AttributeType.VALIDITY_START_TIME.name());
    Element validityEndTimeElement = element.getChild(AttributeType.VALIDITY_END_TIME.name());

    allocationPublicationTime = new EpochEvent(this, PUBLICATION_TIME_OF_ALLOCATION, allocationPublicationTimeElement, actionContext);
    deallocationPublicationTime = new EpochEvent(this, PUBLICATION_TIME_OF_DEALLOCATION, deallocationPublicationTimeElement, actionContext);
    validityStartTime = new EpochEvent(this, VALIDITY_START_TIME_OF_ALLOCATION, validityStartTimeElement, actionContext);
    validityEndTime = new EpochEvent(this, VALIDITY_END_TIME_OF_ALLOCATION, validityEndTimeElement, actionContext);

    @SuppressWarnings("unchecked")
    List<Element> children = element.getChildren(Pair.TAG_PAIR);
    for (Element childElement : children) {
      allocationPairs.add(new Pair(childElement));
    }
  }

  /**
   * @return an element encoding this action
   */
  @Override
  public Element toXML(ActionContext actionContext) {
    Element element = createElement(ActionType.allocate);
    if (parent != null) {
      element.setAttribute(ATTR_PARENT_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_CHILD_NAME, child.commonName);
    element.setAttribute(ATTR_ALLOCATION_ID, allocationId);
    element.setAttribute(ATTR_RANGE_TYPE, rangeType.name());

    element.addContent(allocationPublicationTime.toXML(AttributeType.ALLOCATION_PUBLICATION_TIME.name(), actionContext));
    element.addContent(deallocationPublicationTime.toXML(AttributeType.DEALLOCATION_PUBLICATION_TIME.name(), actionContext));
    element.addContent(validityStartTime.toXML(AttributeType.VALIDITY_START_TIME.name(), actionContext));
    element.addContent(validityEndTime.toXML(AttributeType.VALIDITY_END_TIME.name(), actionContext));

    for (Pair pair : allocationPairs) {
      element.addContent(pair.toXML());
    }
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAllEpochEvents()
   */
  @Override
  public Collection<EpochEvent> getAllEpochEvents() {
    return Arrays.asList(allocationPublicationTime, validityStartTime, deallocationPublicationTime, validityEndTime);
  }

  /**
   * Perform the allocation described
   * 
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(EpochEvent, TypescriptLogger)
   */
  @Override
  public void execute(EpochEvent executionEpoch, TypescriptLogger logger) {
    if (executionEpoch == allocationPublicationTime) {
      switch (rangeType) {
      case ipv4:
        child.takeIPv4(allocationPairs, allocationId);
        break;
      case ipv6:
        child.takeIPv6(allocationPairs, allocationId);
        break;
      case as:
        child.takeAS(allocationPairs, allocationId);
        break;
      }
      if (logger != null) {
        logger.format("Allocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
      }
    } else if (executionEpoch == validityEndTime) {
      child.returnAllocation(rangeType, allocationId);
      if (logger != null) {
        logger.format("Deallocate %s from %s to %s identified as %s%n", allocationPairs, parent, child, allocationId);
      }
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public LinkedHashMap<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.ALLOCATION_ID.getDisplayName(), allocationId);
    ret.put(AttributeType.ISSUER.getDisplayName(), parent);
    ret.put(AttributeType.SUBJECT.getDisplayName(), child);
    ret.put(AttributeType.ALLOCATION_PUBLICATION_TIME.getDisplayName(), allocationPublicationTime);
    ret.put(AttributeType.VALIDITY_START_TIME.getDisplayName(), validityStartTime);
    ret.put(AttributeType.DEALLOCATION_PUBLICATION_TIME.getDisplayName(), deallocationPublicationTime);
    ret.put(AttributeType.VALIDITY_END_TIME.getDisplayName(), validityEndTime);
    ret.put(AttributeType.INR_TYPE.getDisplayName(), rangeType);
    ret.put(AttributeType.ALLOCATIONS.getDisplayName(), allocationPairs);
    return ret;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getId()
   */
  @Override
  public String getId() {
    return allocationId;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Allocate %s: %s from %s to %s", allocationId, rangeType.name(), parent.getNickname(), child.getNickname());
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#updateAttribute(java.lang.String, java.lang.Object)
   */
  @Override
  public void updateAttribute(String label, Object newValue) {
    AttributeType at = AttributeType.forDisplayName(label);
    switch (at) {
    case ALLOCATION_ID:
      allocationId = (String) newValue;
      break;
    case ALLOCATIONS:
      allocationPairs = (PairList) newValue;
      break;
    case INR_TYPE:
      rangeType = (IPRangeType) newValue;
      break;
    case ISSUER:
      parent = (CA_Object) newValue;
      break;
    case SUBJECT:
      child = (CA_Object) newValue;
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
}
