/*
 * Created on Feb 13, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ActionContext {
  private int nextRef = 0;

  private final Map<String, EpochEvent> ref2EpochEvent = new HashMap<String, EpochEvent>();
  private final Map<EpochEvent, String> epochEvent2Ref = new HashMap<EpochEvent, String>();

  /**
   * @param epoch
   * @return the ref for this epoch
   */
  public String getRef(EpochEvent epoch) {
    String ref = epochEvent2Ref.get(epoch);
    if (ref == null) {
      ref = String.valueOf(++nextRef);
      registerEpochEvent(epoch, ref);
    }
    return ref;
  }

  /**
   * @param ref
   * @return the Epoch registered for the ref or null if not yet registered
   */
  public EpochEvent getEpochEvent(String ref) {
    return ref2EpochEvent.get(ref);
  }

  /**
   * @param epoch
   * @param id
   */
  public void registerEpochEvent(EpochEvent epoch, String id) {
    ref2EpochEvent.put(id, epoch);
    epochEvent2Ref.put(epoch, id);
  }

  /**
   * @return the epochs
   */
  public Collection<EpochEvent> getEpochEvents() {
    return epochEvent2Ref.keySet();
  }

}
