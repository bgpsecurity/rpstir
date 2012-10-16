/*
 * Created on Oct 16, 2012
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

import org.jdom.Element;

import com.bbn.rpki.test.actions.XMLConstants;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class TypedPair extends Pair implements XMLConstants {
  public IPRangeType type;

  /**
   * @param element
   */
  public TypedPair(Element element) {
    this(null, element);
  }

  /**
   * @param tag
   * @param arg
   */
  public TypedPair(IPRangeType type, String tag, BigInteger arg) {
    super(tag, arg);
    this.type = type;
  }

  /**
   * @param tag
   * @param arg
   */
  public TypedPair(IPRangeType type, String tag, long arg) {
    super(tag, arg);
    this.type = type;
  }

  /**
   * @param rangeType
   * @param childElement
   */
  public TypedPair(IPRangeType rangeType, Element element) {
    super(element);
    type = rangeType != null ? rangeType : IPRangeType.valueOf(element.getAttributeValue(ATTR_RANGE_TYPE));
  }

  /**
   * @see com.bbn.rpki.test.objects.Pair#toXML()
   */
  @Override
  public Element toXML() {
    Element element = super.toXML();
    element.setAttribute(ATTR_RANGE_TYPE, type.name());
    return element;
  }


}
