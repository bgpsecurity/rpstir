/*
 * Created on Oct 22, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.AllocationId;
import com.bbn.rpki.test.objects.Allocator;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.TypedPair;
import com.bbn.rpki.test.objects.TypedPairList;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public abstract class AllocateActionBase extends AbstractAction {

  protected static final String VALIDITY_END_TIME_OF_ALLOCATION = "Validity End Time of Allocation ";

  protected static final String VALIDITY_START_TIME_OF_ALLOCATION = "Validity Start Time of Allocation ";

  protected static final String PUBLICATION_TIME_OF_DEALLOCATION = "Publication Time of Deallocation ";

  protected static final String PUBLICATION_TIME_OF_ALLOCATION = "Publication Time of Allocation ";

  enum AttributeType {
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

    private final String displayName;
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

  protected TypedPairList allocationPairs = new TypedPairList();
  protected CA_Object parent;
  protected AllocationId allocationId;
  protected final EpochEvent allocationPublicationTime;
  protected final EpochEvent deallocationPublicationTime;
  protected final EpochEvent validityStartTime;
  protected final EpochEvent validityEndTime;

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param rangeType
   * @param model
   * @param pairs the ranges or prefixes to be allocated
   */
  public AllocateActionBase(CA_Object parent, AllocationId allocationId, Model model, TypedPair...pairs) {
    super(model);
    this.parent = parent;
    this.allocationId = allocationId;
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
   * Constructor from xml Element
   * @param element
   * @param model
   * @param actionContext
   */
  public AllocateActionBase(Element element, Model model, ActionContext actionContext) {
    super(model);
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_NAME);
    allocationId = AllocationId.get(element.getAttributeValue(ATTR_ALLOCATION_ID));
    String rangeTypeName = element.getAttributeValue(ATTR_RANGE_TYPE);

    parent = ActionManager.singleton().findCA_Object(parentCommonName);

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
    IPRangeType rangeType;
    if (rangeTypeName != null) {
      // Old style with separate range type
      rangeType = IPRangeType.valueOf(rangeTypeName);
    } else {
      rangeType = null;
    }
    for (Element childElement : children) {
      allocationPairs.add(new TypedPair(rangeType, childElement));
    }
  }

  protected Element appendXML(Element element, ActionContext actionContext) {
    if (parent != null) {
      element.setAttribute(ATTR_PARENT_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_ALLOCATION_ID, allocationId.toString());

    element.addContent(allocationPublicationTime.toXML(AttributeType.ALLOCATION_PUBLICATION_TIME.name(), actionContext));
    element.addContent(deallocationPublicationTime.toXML(AttributeType.DEALLOCATION_PUBLICATION_TIME.name(), actionContext));
    element.addContent(validityStartTime.toXML(AttributeType.VALIDITY_START_TIME.name(), actionContext));
    element.addContent(validityEndTime.toXML(AttributeType.VALIDITY_END_TIME.name(), actionContext));

    for (TypedPair pair : allocationPairs) {
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
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public Map<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.ALLOCATION_ID.getDisplayName(), allocationId);
    ret.put(AttributeType.ISSUER.getDisplayName(), parent);
    maybePutSubject (ret);
    ret.put(AttributeType.ALLOCATION_PUBLICATION_TIME.getDisplayName(), allocationPublicationTime);
    ret.put(AttributeType.VALIDITY_START_TIME.getDisplayName(), validityStartTime);
    ret.put(AttributeType.DEALLOCATION_PUBLICATION_TIME.getDisplayName(), deallocationPublicationTime);
    ret.put(AttributeType.VALIDITY_END_TIME.getDisplayName(), validityEndTime);
    ret.put(AttributeType.ALLOCATIONS.getDisplayName(), allocationPairs);
    return ret;
  }

  /**
   * @param ret
   */
  protected void maybePutSubject(LinkedHashMap<String, Object> ret) {
    // Do nothing by default
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getId()
   */
  @Override
  public AllocationId getId() {
    return allocationId;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#updateAttribute(java.lang.String, java.lang.Object)
   */
  @Override
  public void updateAttribute(String label, Object newValue) {
    AttributeType at = AttributeType.forDisplayName(label);
    switch (at) {
    case ALLOCATION_ID:
      allocationId = (AllocationId) newValue;
      break;
    case ALLOCATIONS:
      allocationPairs = (TypedPairList) newValue;
      break;
    case ISSUER:
      parent = (CA_Object) newValue;
      break;
    case SUBJECT:
      // Handled by subclasses
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
  public void constrainBy(Collection<EpochEvent> otherEpochEvents) {
    for (EpochEvent epochEvent : otherEpochEvents) {
      allocationPublicationTime.addSuccessor(epochEvent, true);
      validityStartTime.addSuccessor(epochEvent, true);
      deallocationPublicationTime.addPredecessor(epochEvent, true);
      validityEndTime.addPredecessor(epochEvent, true);
    }
  }

  /**
   * @return the parent
   */
  public Allocator getParent() {
    return parent;
  }

  /**
   * @return the validity start time event
   */
  public EpochEvent getValidityStartEvent() {
    return validityStartTime;
  }

  /**
   * @return
   */
  public EpochEvent getValidityEndEvent() {
    return validityEndTime;
  }

  @Override
  public List<String> getInvalidReasons() {
    List<String> ret = null;
    if (getId() == null) {
      ret = appendReason(ret, "Allocation Id should be specified");
    }
    return ret;
  }
}
