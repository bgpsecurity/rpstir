/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

import org.jdom.Element;

/**
 * Represents values with a text tag and a numeric value
 *
 * @author RTomlinson
 */
public class Pair {
  /**
   * Element tag used to encode this
   */
  public static final String TAG_PAIR = "pair";

  private static final String ATTR_ARG = "arg";

  private static final String ATTR_TAG = "tag";

  /** The text tag of the value */
  public String tag;

  /** The numeric part of the value */
  public BigInteger arg;

  /**
   * @param tag normally "r" or "p" for range or prefix
   * @param arg
   */
  public Pair(String tag, BigInteger arg) {
    this.tag = tag;
    this.arg = arg;
  }

  /**
   * Construct from long or int
   * @param tag
   * @param arg
   */
  public Pair(String tag, long arg) {
    this(tag, BigInteger.valueOf(arg));
  }

  /**
   * Constructor from xml element
   * @param element
   */
  public Pair(Element element) {
    this.tag = element.getAttributeValue(ATTR_TAG);
    this.arg = new BigInteger(element.getAttributeValue(ATTR_ARG));
  }

  /**
   * @return xml Element encoding this pair
   */
  public Element toXML() {
    Element element = new Element(TAG_PAIR);
    element.setAttribute(ATTR_TAG, tag);
    element.setAttribute(ATTR_ARG, String.valueOf(arg));
    return element;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("%s%%%d", tag, arg);
  }
}
