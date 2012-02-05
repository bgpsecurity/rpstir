/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.Range;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Represents an deallocation action to be performed as part of a test.
 * 
 * Deallocations occur in relation to a previous allocate and have the effect
 * of deallocating some portion of that allocation. Reference to the original
 * allocation is needed because that allocation is expressed in terms of its
 * size and the actual allocated range depends on the resources available at the
 * time of the allocation
 *
 * @author tomlinso
 */
public class DeallocateAction extends AbstractAction {

  enum AttributeType {
    INR_TYPE("INR Type"),
    ISSUER("Issuer"),
    SUBJECT("Subject"),
    ALLOCATION_ID("Allocation Id"),
    ALLOCATION_INDEX("Allocation Index");

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
  }

  private CA_Object parent;
  private CA_Object child;
  private String allocationId;
  private int allocationIndex;
  private IPRangeType rangeType;

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param allocationIndex
   * @param rangeType
   * @param pairs the ranges or prefixes to be allocated
   */
  public DeallocateAction(CA_Object parent, CA_Object child, String allocationId, int allocationIndex, IPRangeType rangeType, Pair...pairs) {
    this.parent = parent;
    this.child = child;
    this.allocationId = allocationId;
    this.allocationIndex = allocationIndex;
    this.rangeType = rangeType;
  }

  /**
   * Default constructor must have a model to make any sense
   * @param model
   */
  public DeallocateAction(Model model) {
    this(model.getRootCA(), model.getRootCA().getChild(0), "", 0, IPRangeType.ipv4);
  }

  /**
   * Constructor from xml Element
   * @param element
   */
  public DeallocateAction(Element element) {
    String commonName = element.getAttributeValue(ATTR_CHILD_NAME);
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_NAME);
    allocationId = element.getAttributeValue(ATTR_ALLOCATION_ID);
    allocationIndex = Integer.parseInt(element.getAttributeValue(ATTR_ALLOCATION_INDEX));
    rangeType = IPRangeType.valueOf(element.getAttributeValue(ATTR_TYPE));
    parent = ActionManager.singleton().findCA_Object(parentCommonName);
    child = ActionManager.singleton().findCA_Object(commonName);
  }

  /**
   * @return an element encoding this action
   */
  @Override
  public Element toXML() {
    Element element = createElement(VALUE_DEALLOCATE);
    if (parent != null) {
      element.setAttribute(ATTR_PARENT_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_CHILD_NAME, child.commonName);
    element.setAttribute(ATTR_ALLOCATION_ID, allocationId);
    element.setAttribute(ATTR_ALLOCATION_INDEX, String.valueOf(allocationIndex));
    element.setAttribute(ATTR_TYPE, rangeType.name());
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(TypescriptLogger)
   */
  @Override
  public void execute(TypescriptLogger logger) {
    Range range = ActionManager.singleton().findAllocation(rangeType, allocationId, allocationIndex);
    child.removeRange(rangeType, range);
    parent.addRange(rangeType, range);
    if (logger != null) {
      logger.format("Deallocate %s from %s.%d of %s to %s%n", range, allocationId, allocationIndex, child, parent);
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public LinkedHashMap<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.INR_TYPE.getDisplayName(), rangeType);
    ret.put(AttributeType.ISSUER.getDisplayName(), parent);
    ret.put(AttributeType.SUBJECT.getDisplayName(), child);
    ret.put(AttributeType.ALLOCATION_ID.getDisplayName(), allocationId);
    ret.put(AttributeType.ALLOCATION_INDEX.getDisplayName(), allocationIndex);
    return ret;
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
    case ALLOCATION_INDEX:
      allocationIndex = (Integer) newValue;
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
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Deallocate %s:%d from %s to %s", allocationId, allocationIndex, parent.getNickname(), child.getNickname());
  }
}
