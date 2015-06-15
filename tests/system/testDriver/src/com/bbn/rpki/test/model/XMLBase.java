/*
 * Created on Oct 31, 2011
 */
package com.bbn.rpki.test.model;

import java.util.List;

import org.jdom.Element;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class XMLBase {

  /**
   * @param element
   * @param tag
   * @return
   */
  @SuppressWarnings("unchecked")
  protected List<Element> getChildren(Element element, String tag) {
    return element.getChildren(tag);
  }

}
