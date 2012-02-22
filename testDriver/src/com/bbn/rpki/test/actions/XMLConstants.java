/*
 * Created on Feb 13, 2012
 */
package com.bbn.rpki.test.actions;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public interface XMLConstants {

  /** Tag or attribute name */
  static final String TAG_ACTION = "action";

  /** Tag or attribute name */
  static final String TAG_EPOCH = "epoch";

  /** Tag or attribute name */
  static final String ATTR_TYPE = "type";

  /** Tag or attribute name */
  static final String ATTR_ALLOCATION_ID = "allocationId";

  /** Tag or attribute name */
  static final String ATTR_ALLOCATION_INDEX = "allocationIndex";

  /** Tag or attribute name */
  static final String ATTR_PARENT_NAME = "parentName";

  /** Tag or attribute name */
  static final String ATTR_CHILD_NAME = "childName";

  /** Tag or attribute name */
  static final String ATTR_EPOCH_INDEX = "epoch-index";

  /** Tag or attribute name */
  static final String ATTR_ACTION_TYPE = "actionType";

  /** Tag or attribute name */
  static final String ATTR_REF = "ref";

  /** Tag or attribute name */
  static final String ATTR_LOCKED = "locked";

  /** Tag or attribute name */
  static final String TAG_COINCIDENT = "coincident";

  /** Tag or attribute name */
  static final String TAG_PREDECESSOR = "predecessor";

  /** Tag or attribute name */
  static final String TAG_SUCCESSOR = "successor";

  /** Tag or attribute name */
  static final String ATTR_ID = "id";

  /** Tag or attribute name */
  static final String ATTR_PATH = "path";

  /** Tag or attribute name */
  static final String VALUE_ALLOCATE = "allocate";

  /** Tag or attribute name */
  static final String VALUE_DEALLOCATE = "deallocate";

  /** Tag or attribute name */
  static final String VALUE_CHOOSE_CACHE_CHECK_TASK = "choose-check-task";
}
