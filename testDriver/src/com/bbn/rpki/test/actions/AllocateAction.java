/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jdom.Element;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.TypescriptLogger;

/**
 * Represents an allocation action to be performed as part of a test.
 *
 * @author tomlinso
 */
public class AllocateAction extends AbstractAction {

  private final List<Pair> allocationPairs = new ArrayList<Pair>();
  private final CA_Object parent;
  private final CA_Object child;
  private final String allocationId;
  private final IPRangeType rangeType;

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
   * Constructor from xml Element
   * @param element
   */
  public AllocateAction(Element element) {
    String commonName = element.getAttributeValue(ATTR_COMMON_NAME);
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_COMMON_NAME);
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
      element.setAttribute(ATTR_PARENT_COMMON_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_COMMON_NAME, child.commonName);
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
}
