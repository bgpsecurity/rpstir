/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Arrays;
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

  enum AttributeType {
    INR_TYPE("INR Type"),
    ISSUER("Issuer"),
    SUBJECT("Subject"),
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

  /**
   * @param parent
   * @param child
   * @param allocationId
   * @param rangeType
   * @param pairs the ranges or prefixes to be allocated
   */
  public AllocateAction(CA_Object parent, CA_Object child, String allocationId, IPRangeType rangeType, Pair...pairs) {
    this.parent = parent;
    this.child = child;
    this.allocationId = allocationId;
    this.rangeType = rangeType;
    this.allocationPairs.addAll(Arrays.asList(pairs));
  }

  /**
   * Default constructor must have a model to make any sense
   * @param model
   */
  public AllocateAction(Model model) {
    this(model.getRootCA(), model.getRootCA().getChild(0), "", IPRangeType.ipv4);
  }

  /**
   * Constructor from xml Element
   * @param element
   */
  public AllocateAction(Element element) {
    String commonName = element.getAttributeValue(ATTR_CHILD_NAME);
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_NAME);
    allocationId = element.getAttributeValue(ATTR_ALLOCATION_ID);
    parent = ActionManager.singleton().findCA_Object(parentCommonName);
    child = ActionManager.singleton().findCA_Object(commonName);
    rangeType = IPRangeType.valueOf(element.getAttributeValue(ATTR_TYPE));
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
  public Element toXML() {
    Element element = createElement(VALUE_ALLOCATE);
    if (parent != null) {
      element.setAttribute(ATTR_PARENT_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_CHILD_NAME, child.commonName);
    element.setAttribute(ATTR_ALLOCATION_ID, allocationId);
    for (Pair pair : allocationPairs) {
      element.addContent(pair.toXML());
    }
    return element;
  }

  /**
   * Perform the allocation described
   * 
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(TypescriptLogger)
   */
  @Override
  public void execute(TypescriptLogger logger) {
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
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public LinkedHashMap<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.ISSUER.getDisplayName(), parent);
    ret.put(AttributeType.SUBJECT.getDisplayName(), child);
    ret.put(AttributeType.ALLOCATION_ID.getDisplayName(), allocationId);
    ret.put(AttributeType.INR_TYPE.getDisplayName(), rangeType);
    ret.put(AttributeType.ALLOCATIONS.getDisplayName(), allocationPairs);
    return ret;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Allocate %s from %s to %s", rangeType.name(), parent.getNickname(), child.getNickname());
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
}
