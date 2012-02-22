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

  private final Map<String, Epoch> ref2Epoch = new HashMap<String, Epoch>();
  private final Map<Epoch, String> epoch2Ref = new HashMap<Epoch, String>();

  /**
   * @param epoch
   * @return the ref for this epoch
   */
  public String getRef(Epoch epoch) {
    String ref = epoch2Ref.get(epoch);
    if (ref == null) {
      ref = String.valueOf(++nextRef);
      registerEpoch(epoch, ref);
    }
    return ref;
  }

  /**
   * @param ref
   * @return the Epoch registered for the ref or null if not yet registered
   */
  public Epoch getEpoch(String ref) {
    return ref2Epoch.get(ref);
  }

  /**
   * @param epoch
   * @param id
   */
  public void registerEpoch(Epoch epoch, String id) {
    ref2Epoch.put(id, epoch);
    epoch2Ref.put(epoch, id);
  }

  /**
   * @return the epochs
   */
  public Collection<Epoch> getEpochs() {
    return epoch2Ref.keySet();
  }

}
