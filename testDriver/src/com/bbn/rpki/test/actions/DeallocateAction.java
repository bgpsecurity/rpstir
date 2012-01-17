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
import com.bbn.rpki.test.objects.Range;
import com.bbn.rpki.test.objects.TypescriptLogger;

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

  private final List<Pair> allocationPairs = new ArrayList<Pair>();
  private final CA_Object parent;
  private final CA_Object child;
  private final String allocationId;
  private final int allocationIndex;
  private final IPRangeType rangeType;

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
    this.allocationPairs.addAll(Arrays.asList(pairs));
  }

  /**
   * Constructor from xml Element
   * @param element
   */
  public DeallocateAction(Element element) {
    String commonName = element.getAttributeValue(ATTR_COMMON_NAME);
    String parentCommonName = element.getAttributeValue(ATTR_PARENT_COMMON_NAME);
    allocationId = element.getAttributeValue(ATTR_ALLOCATION_ID);
    allocationIndex = Integer.parseInt(element.getAttributeValue(ATTR_ALLOCATION_INDEX));
    rangeType = IPRangeType.valueOf(element.getAttributeValue(ATTR_TYPE));
    parent = ActionManager.singleton().findCA_Object(parentCommonName);
    child = ActionManager.singleton().findCA_Object(commonName);
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
    Element element = createElement(VALUE_DEALLOCATE);
    if (parent != null) {
      element.setAttribute(ATTR_PARENT_COMMON_NAME, parent.commonName);
    }
    element.setAttribute(ATTR_COMMON_NAME, child.commonName);
    element.setAttribute(ATTR_ALLOCATION_ID, allocationId);
    element.setAttribute(ATTR_ALLOCATION_INDEX, String.valueOf(allocationIndex));
    element.setAttribute(ATTR_TYPE, rangeType.name());
    for (Pair pair : allocationPairs) {
      element.addContent(pair.toXML());
    }
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
}
